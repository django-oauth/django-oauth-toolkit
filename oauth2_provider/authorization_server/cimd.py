"""
OAuth Client ID Metadata Document (CIMD) support.

Implements ``draft-ietf-oauth-client-id-metadata-document-01``: a client
identifies itself with an ``https`` URL as its ``client_id``; the authorization
server fetches that URL to retrieve the client's metadata (the same shape as
RFC 7591 Dynamic Client Registration) and resolves it to an Application. See
``rfcs/draft-ietf-oauth-client-id-metadata-document-01.txt``.

The fetch is an outbound request to a client-controlled URL made inside the
authorization request flow, so the default fetcher is hardened against SSRF
(https only, resolve and validate the target IP once then connect to that same
IP, no redirects, tight timeouts, response size cap) and the resolver bounds
the cost of a flood of bad URLs with a per-URL failure backoff and an in-flight
concurrency cap. See ``docs/cimd.rst`` for the threat model.
"""

import contextlib
import hashlib
import json
import logging
import re
import threading
from datetime import timedelta
from typing import Any
from urllib.parse import urlparse

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.http.request import validate_host
from django.utils import timezone
from oauthlib.common import Request

from oauth2_provider.authorization_server.oidc.client_metadata import (
    UnsupportedClientMetadataError,
    id_token_signing_algorithm,
    userinfo_signing_algorithm,
)
from oauth2_provider.core import safe_fetch

# Re-exported for backward compatibility: NAT64_PREFIX was a public module constant
# of oauth2_provider.cimd through 3.4.1. The NAT64 check moved into the shared
# SSRF-hardened fetcher, so keep the old name importable from this module.
from oauth2_provider.core.safe_fetch import NAT64_PREFIX  # noqa: F401
from oauth2_provider.models import AbstractApplication, get_application_model
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger(__name__)

# RFC 7591 grant_type name → DOT AbstractApplication.authorization_grant_type.
# Mirrors GRANT_TYPE_MAP in views/dynamic_client_registration.py; kept as a
# separate subset here because only redirect-based grants are offered to CIMD
# clients (client_credentials is intentionally absent, even for a client that
# authenticates with private_key_jwt) and device_code is out of scope for CIMD
# (its grant would also need DeviceGrant.client_id widened to hold a URL).
GRANT_TYPE_MAP = {
    "authorization_code": "authorization-code",
    "implicit": "implicit",
}
# Implied by authorization_code (DOT issues refresh tokens alongside it), so it is
# never registered on its own and never reported as a dropped grant.
IGNORED_GRANT_TYPES = {"refresh_token"}

# Every method a CIMD registration can be stored with. Shared-secret methods
# are forbidden by the spec (section 4.1); ``private_key_jwt`` is the one
# asymmetric method RFC 7523 client authentication implements. Which of these a
# given server registers is decided by :func:`_supported_auth_methods`.
REGISTRABLE_AUTH_METHODS = ("none", "private_key_jwt")
# Section 4.1: a document MUST NOT declare any method built on a shared symmetric
# secret, because there is no way to establish one. Rejected on sight, before any
# negotiation, so a forbidden declaration cannot be rescued by the plural field.
SHARED_SECRET_AUTH_METHODS = frozenset({"client_secret_basic", "client_secret_post", "client_secret_jwt"})

# Cache-freshness lives on the model (cimd_expires_at, durable and authoritative
# per row); the failure backoff is ephemeral/best-effort, so it lives in the
# cache under this prefix.
BACKOFF_CACHE_PREFIX = "oauth2_provider:cimd:backoff:"
MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

# The in-flight cap is a per-process BoundedSemaphore, rebuilt when the
# configured size changes (e.g. between tests). Across N server processes the
# real ceiling is size × N; see docs/cimd.rst.
_semaphore_lock = threading.Lock()
_semaphore = None
_semaphore_size = None


class CIMDError(Exception):
    """A client ID metadata document could not be resolved.

    The message is safe to log but is never returned to the client: a failed
    resolution simply looks like an unknown client to the OAuth flow.
    """


class CIMDPolicyError(CIMDError):
    """This server's policy refuses a document that is otherwise acceptable.

    Raised when a document chooses an authentication method this server could
    register but does not (see :func:`_supported_auth_methods`). It is not a
    fetch or validation failure, so the resolver does not arm the shared failure
    backoff for it: that backoff is shared by every node using the cache, and a
    refusal by one node must not block the nodes whose policy accepts the
    document. It arms a policy backoff instead (see
    :func:`_policy_backoff_cache_key`), whose key includes a digest of this
    node's policy: refetches are bounded, nodes with the same policy share the
    backoff, nodes with a different policy never see it, and a policy change
    takes effect at once.
    """


def is_cimd_client_id(client_id):
    """Return True if *client_id* looks like a CIMD URL.

    Cheap gate so ordinary (non-URL) client_ids skip all CIMD machinery. The
    scheme is matched case-insensitively (RFC 3986 section 3.1) to stay
    consistent with :func:`_validate_client_id_url`, where full validation
    happens.
    """
    return bool(client_id) and client_id[:8].lower() == "https://"


class AllowAllCIMDPermission:
    """Allow any CIMD client_id URL to register (default).

    Registration happens on the pre-auth authorize/token path, where no
    authenticated user exists, so unlike DCR the default is open.

    The interface mirrors DCR's request-first ``has_permission``. *request* is
    the oauthlib request the client_id arrived on; its ``headers`` carry the
    HTTP headers, for e.g. IP-bound policies.
    """

    def has_permission(self, request, client_id) -> bool:
        return True


class HostAllowlistCIMDPermission:
    """Allow only client_id URLs whose host matches ``CIMD_ALLOWED_HOSTS``.

    Entries use Django's ``ALLOWED_HOSTS`` syntax: an exact hostname,
    ``".example.com"`` for a domain and all its subdomains, or ``"*"``.
    An empty allowlist denies every host.
    """

    def has_permission(self, request, client_id) -> bool:
        host = urlparse(client_id).hostname
        return bool(host) and validate_host(host, oauth2_settings.CIMD_ALLOWED_HOSTS or [])


def _registration_permitted(request, client_id):
    """Run all CIMD_REGISTRATION_PERMISSION_CLASSES; return True if all pass.

    Fails closed: an empty setting denies all registration, matching the DCR
    permission-class semantics.
    """
    permission_classes = oauth2_settings.CIMD_REGISTRATION_PERMISSION_CLASSES
    if not permission_classes:
        return False
    return all(cls().has_permission(request, client_id) for cls in permission_classes)


def _validate_client_id_url(client_id):
    """Validate and parse the client_id URL per the CIMD spec (section 3).

    The URL MUST use https, contain a host, a valid port and a path, MUST NOT
    carry a userinfo or fragment component, and MUST NOT contain single-dot or
    double-dot path segments. Raises :class:`CIMDError` otherwise.
    """
    parsed = urlparse(client_id)
    if parsed.scheme != "https":
        raise CIMDError("client_id URL must use the https scheme")
    if not parsed.hostname:
        raise CIMDError("client_id URL must contain a host")
    try:
        _ = parsed.port  # an out-of-range port raises ValueError on access
    except ValueError as exc:
        raise CIMDError("client_id URL has an invalid port") from exc
    if parsed.username or parsed.password:
        raise CIMDError("client_id URL must not contain a userinfo component")
    if parsed.fragment:
        raise CIMDError("client_id URL must not contain a fragment component")
    if not parsed.path:
        raise CIMDError("client_id URL must contain a path component")
    if any(segment in (".", "..") for segment in parsed.path.split("/")):
        raise CIMDError("client_id URL must not contain dot path segments")
    return parsed


def _ip_is_public(ip_str):
    """Return True only for a globally routable address (see safe_fetch)."""
    return safe_fetch.ip_is_public(ip_str)


def _resolve_and_validate(hostname, port):
    """Resolve *hostname* and return its validated IPs, or raise CIMDError.

    Every resolved address must be public; if any is internal the whole host
    is refused. See :func:`safe_fetch.resolve_and_validate`.
    """
    return safe_fetch.resolve_and_validate(hostname, port, exc_class=CIMDError)


def _effective_max_age(cache_control):
    """Derive a cache lifetime (seconds) from a Cache-Control header value.

    Honours ``max-age`` when present, treats ``no-store``/``no-cache`` as the
    configured floor (we still persist the Application for the FK, but re-fetch
    soon), and otherwise defaults to the configured ceiling. The result is
    always clamped to [MIN_AGE, MAX_AGE].
    """
    floor = oauth2_settings.CIMD_METADATA_MIN_AGE_SECONDS
    ceiling = oauth2_settings.CIMD_METADATA_MAX_AGE_SECONDS
    age = ceiling
    if cache_control:
        lowered = cache_control.lower()
        if "no-store" in lowered or "no-cache" in lowered:
            age = floor
        else:
            match = MAX_AGE_RE.search(cache_control)
            if match:
                age = int(match.group(1))
    return max(floor, min(age, ceiling))


class SafeMetadataFetcher:
    """Default SSRF-hardened fetcher for CIMD documents.

    Override with the ``CIMD_METADATA_FETCHER`` setting to route through an
    egress proxy or apply site-specific policy. A fetcher's ``fetch(client_id)``
    must return ``(metadata_dict, max_age_seconds)`` or raise
    :class:`CIMDError`.
    """

    def fetch(self, client_id):
        _validate_client_id_url(client_id)
        # The SSRF hardening (IP validation and pinning, no redirects, shared
        # deadline across every resolved address) lives in safe_fetch; the
        # CIMD-specific pieces are the URL validation above and the response
        # handling (size cap, Cache-Control-derived max_age) in _read_document.
        return safe_fetch.fetch_https_document(
            client_id,
            timeout=oauth2_settings.CIMD_FETCH_TIMEOUT_SECONDS,
            read_response=self._read_document,
            exc_class=CIMDError,
        )

    def _read_document(self, response):
        if response.status != 200:
            raise CIMDError(f"client_id document returned HTTP {response.status}")
        # Accept application/json and the RFC 6839 structured suffix
        # application/<subtype>+json (the spec permits AS-defined JSON types).
        if not safe_fetch.media_type_is_json(response.headers.get("Content-Type", "")):
            media_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            raise CIMDError(f"client_id document is not JSON (Content-Type: {media_type!r})")

        max_size = oauth2_settings.CIMD_MAX_DOCUMENT_SIZE
        body = response.read(max_size + 1)
        if len(body) > max_size:
            raise CIMDError("client_id document exceeds the maximum allowed size")

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            raise CIMDError("client_id document is not valid JSON") from exc
        if not isinstance(data, dict):
            raise CIMDError("client_id document must be a JSON object")

        return data, _effective_max_age(response.headers.get("Cache-Control"))


def _resolve_grant_type(grant_types: list[str]) -> str:
    """Resolve an RFC 7591 grant_types list to a single DOT grant constant.

    Entries this server does not register for CIMD clients are dropped instead of
    failing the whole document, and the document is refused only when nothing
    supported remains. This is server policy: the CIMD draft defines no exchange
    through which the server could report the metadata it applied. It follows the
    precedent of RFC 7591 section 2, which lets a registration server replace
    requested values "with suitable defaults as described in Section 3.2.1".
    Published clients rely on it: Claude's client metadata declares ``jwt-bearer``
    next to the ``authorization_code`` its connector actually uses.

    ``Application`` stores a single grant, so one of the supported entries has to win.
    ``authorization_code`` does: it is the only grant a ``private_key_jwt`` client may
    use, and RFC 9700 section 2.1.2 advises clients against the implicit grant.
    """
    supported = [g for g in grant_types if g in GRANT_TYPE_MAP]
    if not supported:
        raise CIMDError("client metadata declares no grant_type this server supports")
    preferred = "authorization_code" if "authorization_code" in supported else supported[0]
    return GRANT_TYPE_MAP[preferred]


def _dropped_grant_types(grant_types: list[str], registered: str) -> list[str]:
    """Return the declared grant types a registration for *registered* leaves out.

    ``refresh_token`` is implied by ``authorization_code``, so it is never reported.
    """
    return [
        g
        for g in dict.fromkeys(grant_types)
        if g not in IGNORED_GRANT_TYPES and GRANT_TYPE_MAP.get(g) != registered
    ]


def _supported_auth_methods() -> tuple[str, ...]:
    """Return the methods this server registers CIMD clients with.

    ``none`` is always registrable, although the default advertised lists do
    not name it. ``private_key_jwt`` is registrable only when it is advertised
    in the RFC 8414 document (``OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED``)
    and, with OpenID Connect enabled, in the OpenID Connect Discovery document
    (``OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED``) as well: a document
    declares a single method, which its client may have picked from either
    discovery document.
    """
    advertised = set(oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED)
    if oauth2_settings.OIDC_ENABLED:
        advertised.intersection_update(oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED)
    return tuple(m for m in REGISTRABLE_AUTH_METHODS if m == "none" or m in advertised)


def _jwks_uri(metadata: dict[str, Any]) -> Any:
    """Return the document's ``jwks_uri``, or None when it is absent.

    An empty or whitespace-only string counts as absent, as for Dynamic Client
    Registration; any other value is returned (stripped, if a string) for the
    caller to validate.
    """
    jwks_uri = metadata.get("jwks_uri")
    if isinstance(jwks_uri, str):
        return jwks_uri.strip() or None
    return jwks_uri


def _resolve_auth_method(metadata: dict[str, Any]) -> str:
    """Resolve the token_endpoint_auth_method a CIMD registration is stored with.

    The method a document chooses wins whenever this server registers it (see
    :func:`_supported_auth_methods`): the spec (section 6.2) has the authorization
    server require client authentication of the registered type, so a client that
    asked for an asymmetric method is never downgraded to a public one.

    A document may also list every method it can use in
    ``token_endpoint_auth_methods_supported``. Section 4.1 takes client metadata from
    the IANA OAuth client metadata registry, where OpenID Connect RP Metadata Choices
    1.0 registers it; its section 4 has the server use one of the listed values it
    supports rather than fail on an unsupported single value. When the chosen method
    is not one this server registers, the first offered method it does register is
    used instead. Published clients rely on it: ChatGPT's document chooses
    ``private_key_jwt`` and offers ``["none", "private_key_jwt"]``, so a server that
    does not advertise ``private_key_jwt`` registers it as the public client it can
    also be, while one that does advertise it honours the choice.

    Both fields are validated as the rest of the document is: the single value must
    be a string and the plural one an array of strings, a declared shared-secret
    method is rejected outright (section 4.1) before any negotiation, and a declared
    method must appear in the plural list when both are present (RP Metadata Choices
    section 2). A document that omits the single value is read as choosing ``none``
    unless it carries a plural list, in which case the list alone decides.

    A document refused because the methods it names are registrable but not
    advertised here raises :class:`CIMDPolicyError`, as the single-valued check does,
    so the refusal arms the policy backoff rather than the shared failure backoff.
    """
    supported = _supported_auth_methods()
    declared_present = "token_endpoint_auth_method" in metadata
    declared = metadata["token_endpoint_auth_method"] if declared_present else "none"
    if not isinstance(declared, str):
        raise CIMDError("token_endpoint_auth_method must be a string")
    if declared in SHARED_SECRET_AUTH_METHODS:
        raise CIMDError(f"CIMD clients must not use shared-secret token_endpoint_auth_method {declared!r}")

    if "token_endpoint_auth_methods_supported" not in metadata:
        if declared in supported:
            return declared
        error_class = CIMDPolicyError if declared in REGISTRABLE_AUTH_METHODS else CIMDError
        raise error_class(
            f"client metadata declares token_endpoint_auth_method {declared!r}; "
            f"this server registers CIMD clients with {list(supported)}"
        )

    offered = metadata["token_endpoint_auth_methods_supported"]
    if not isinstance(offered, list) or not all(isinstance(m, str) for m in offered):
        raise CIMDError("token_endpoint_auth_methods_supported must be an array of strings")
    if declared_present and declared not in offered:
        raise CIMDError(
            f"token_endpoint_auth_method {declared!r} is not in token_endpoint_auth_methods_supported"
        )
    if declared_present and declared in supported:
        return declared

    for method in offered:
        if method in supported:
            return method

    registrable = declared in REGISTRABLE_AUTH_METHODS or any(m in REGISTRABLE_AUTH_METHODS for m in offered)
    error_class = CIMDPolicyError if registrable else CIMDError
    raise error_class(
        f"client metadata offers token_endpoint_auth_methods_supported {offered!r}; "
        f"this server registers CIMD clients with {list(supported)}"
    )


def _build_application_kwargs(metadata: dict[str, Any]) -> dict[str, Any]:
    """Convert a CIMD metadata document to Application field kwargs.

    Resolves the client authentication method with :func:`_resolve_auth_method`:
    ``"none"``, or ``"private_key_jwt"`` when advertised, negotiated from the
    document's ``token_endpoint_auth_methods_supported`` when the method it chose
    is not registrable here. The spec forbids shared-secret methods, so they are
    never registered. A document may not carry both ``jwks`` and ``jwks_uri``,
    whatever its method. A ``private_key_jwt`` client must use the
    authorization code grant and publish one of ``jwks`` or an HTTPS
    ``jwks_uri`` so its assertion can be verified at the token endpoint, and is
    stored as a confidential client with that key source. Rejects any
    ``client_secret`` property, and requires at least one redirect URI. The ID Token signing algorithm follows
    ``id_token_signed_response_alg`` (OpenID Connect Dynamic Client
    Registration 1.0 section 2). Returns kwargs; raises :class:`CIMDError` on
    invalid metadata.
    """
    auth_method = _resolve_auth_method(metadata)
    # Spec: neither property may appear in a CIMD document (presence, not value).
    if "client_secret" in metadata or "client_secret_expires_at" in metadata:
        raise CIMDError("CIMD client metadata must not include client_secret or client_secret_expires_at")

    # Only redirect-based grants are supported, and those require registered
    # redirect URIs (RFC 7591 section 2), so an empty list would persist an
    # unusable Application row.
    redirect_uris = metadata.get("redirect_uris")
    if (
        not isinstance(redirect_uris, list)
        or not redirect_uris
        or not all(isinstance(u, str) for u in redirect_uris)
    ):
        raise CIMDError("redirect_uris must be a non-empty array of strings")

    grant_types = metadata.get("grant_types", ["authorization_code"])
    if not isinstance(grant_types, list) or not all(isinstance(g, str) for g in grant_types):
        raise CIMDError("grant_types must be an array of strings")

    client_name = metadata.get("client_name", "")
    if not isinstance(client_name, str):
        raise CIMDError("client_name must be a string")

    # Derived on every fetch, so a re-fetch tracks the server's current signing
    # capability: a row provisioned with the RS256 default drops it once the
    # key is gone instead of failing model validation on every refresh (which
    # would freeze the row on its old document for good). A document that asks
    # for RS256 explicitly is refused in that state like any other document the
    # server cannot honour, and the last good row stays in service.
    try:
        algorithm = id_token_signing_algorithm(metadata)
        userinfo_algorithm = userinfo_signing_algorithm(metadata)
    except UnsupportedClientMetadataError as exc:
        raise CIMDError(str(exc)) from exc

    kwargs = {
        "name": client_name,
        "redirect_uris": " ".join(redirect_uris),
        "authorization_grant_type": _resolve_grant_type(grant_types),
        "algorithm": algorithm,
        "userinfo_signed_response_alg": userinfo_algorithm,
        "token_endpoint_auth_method": auth_method,
        # Always emitted, so a re-fetch whose document changed method clears
        # the key source the previous document registered.
        "client_type": AbstractApplication.CLIENT_PUBLIC,
        "client_jwks": "",
        "client_jwks_uri": "",
    }
    # RFC 7591 section 2: the two MUST NOT both be present, whatever the method
    # (a blank jwks_uri counts as absent, as for Dynamic Client Registration).
    jwks = metadata.get("jwks")
    jwks_uri = _jwks_uri(metadata)
    if jwks is not None and jwks_uri is not None:
        raise CIMDError("jwks and jwks_uri are mutually exclusive")
    if auth_method == AbstractApplication.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT:
        # Draft section 6.2: a client registered this way is confidential and
        # "any communication with the authorization server MUST include
        # client authentication of the registered type". The implicit grant
        # issues tokens at the authorization endpoint with no client
        # authentication at all, so the keys would only unlock introspection
        # and client-protected resources.
        if kwargs["authorization_grant_type"] != AbstractApplication.GRANT_AUTHORIZATION_CODE:
            raise CIMDError("private_key_jwt requires the authorization_code grant")
        # Shape checks only, so a malformed document is refused with a precise
        # message before the database is touched. The key material itself
        # (public keys only, at least one usable for signature verification)
        # is validated by Application.clean() when the row is saved, exactly
        # as for a manually registered client.
        if jwks is None and jwks_uri is None:
            raise CIMDError("private_key_jwt requires one of jwks or jwks_uri")
        if jwks_uri is not None:
            if not isinstance(jwks_uri, str) or not jwks_uri.lower().startswith("https://"):
                raise CIMDError("jwks_uri must use the https scheme")
            kwargs["client_jwks_uri"] = jwks_uri
        else:
            if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
                raise CIMDError('jwks must be a JWK Set object with a "keys" array')
            if not jwks["keys"] or not all(isinstance(key, dict) for key in jwks["keys"]):
                raise CIMDError("jwks must contain at least one key, each a JSON object")
            # Canonical member and array order, so a re-fetch whose document
            # merely reordered the set (or the keys within it) is not logged as
            # publishing new keys. The order of a JWK Set's keys carries no
            # meaning (RFC 7517 section 5.1), so the stored set is equivalent.
            keys = sorted(jwks["keys"], key=lambda key: json.dumps(key, sort_keys=True))
            kwargs["client_jwks"] = json.dumps({**jwks, "keys": keys}, sort_keys=True)
        kwargs["client_type"] = AbstractApplication.CLIENT_CONFIDENTIAL
    # Logged only once the whole document has passed, so a document refused on a
    # later field never leaves a notice saying it was registered.
    declared = metadata.get("token_endpoint_auth_method")
    if declared is not None and declared != auth_method:
        log.info(
            "CIMD client %r chose token_endpoint_auth_method %r, which this server "
            "does not register; using the offered %r instead",
            metadata.get("client_id"),
            declared,
            auth_method,
        )
    return kwargs


def _get_fetch_semaphore():
    """Return the in-flight fetch semaphore, or None when the cap is disabled."""
    global _semaphore, _semaphore_size
    size = oauth2_settings.CIMD_MAX_CONCURRENT_FETCHES
    if not size:
        return None
    with _semaphore_lock:
        if _semaphore is None or _semaphore_size != size:
            _semaphore = threading.BoundedSemaphore(size)
            _semaphore_size = size
        return _semaphore


@contextlib.contextmanager
def _fetch_slot():
    """Take an in-flight fetch slot without blocking.

    Yields True when a slot was taken (or the cap is disabled), False when the
    in-flight cap is already full, and releases the slot on exit if one was
    held. Non-blocking so a flood of distinct URLs fails fast rather than
    queuing and tying up workers.
    """
    semaphore = _get_fetch_semaphore()
    acquired = semaphore is None or semaphore.acquire(blocking=False)
    try:
        yield acquired
    finally:
        if acquired and semaphore is not None:
            semaphore.release()


def _fetch_validate_upsert(client_id: str) -> AbstractApplication:
    """Fetch, validate and upsert the Application for a CIMD *client_id*."""
    fetcher = oauth2_settings.CIMD_METADATA_FETCHER()
    metadata, max_age = fetcher.fetch(client_id)

    # Spec: the document's client_id MUST equal the URL it was fetched from.
    # This binds the metadata to its URL, so a document cannot claim to be a
    # different client (and cannot poison another URL's Application row).
    if metadata.get("client_id") != client_id:
        raise CIMDError("document client_id does not match the client_id URL")

    kwargs = _build_application_kwargs(metadata)

    Application = get_application_model()
    try:
        application = Application.objects.get(client_id=client_id)
        if application.registration_source != Application.RegistrationSource.CIMD:
            # A manually provisioned client happens to own this id; never let a
            # fetched document take it over.
            raise CIMDError("client_id URL collides with a non-CIMD application")
        created = False
    except Application.DoesNotExist:
        application = Application(client_id=client_id)
        # Tracked explicitly: a swapped model whose primary key has a default
        # (e.g. a UUIDField with default=uuid4) has a pk before it is saved.
        created = True
    # None for a first sight; otherwise the algorithm the row had before this
    # fetch, so a change is logged (it is derived from this process's settings
    # and persisted for every node sharing the database).
    previous_algorithm = None if created else application.algorithm
    # Likewise for the client's credentials, so a method change or a key
    # rotation (draft section 6.3.1) is visible to an operator. Rows stored
    # before the method was recorded carry the blank default; every one of them
    # was public, so read it as ``none`` rather than log a change on the first
    # re-fetch of every such client.
    previous_auth_method = (
        None if created else (application.token_endpoint_auth_method or Application.TOKEN_AUTH_METHOD_NONE)
    )
    previous_keys = None if created else (application.client_jwks, application.client_jwks_uri)

    application.user = None
    application.registration_source = Application.RegistrationSource.CIMD
    application.cimd_expires_at = timezone.now() + timedelta(seconds=max_age)
    for field, value in kwargs.items():
        setattr(application, field, value)

    try:
        # validate_unique=False: client_id is the only unique field and is
        # server-controlled (the validated URL). Letting full_clean pre-check it
        # would, under a concurrent first-sight race, surface the winner's row as
        # a ValidationError on the loser and fail a valid client; instead the DB
        # constraint plus the IntegrityError handler below are the sole arbiter.
        application.full_clean(exclude=["client_secret"], validate_unique=False)
    except ValidationError as exc:
        messages = "; ".join(exc.messages)
        raise CIMDError(f"invalid client metadata: {messages}") from exc

    try:
        application.save()
    except IntegrityError as exc:
        # Concurrent first-sight of the same URL: another request won the race.
        # Re-load the winner and re-apply the non-CIMD collision guard.
        try:
            application = Application.objects.get(client_id=client_id)
        except Application.DoesNotExist:
            raise CIMDError("client_id row vanished during a concurrent upsert") from exc
        if application.registration_source != Application.RegistrationSource.CIMD:
            raise CIMDError("client_id URL collides with a non-CIMD application")
    else:
        # Logged only once the row is saved, so a document refused by the
        # collision guard or by model validation never leaves a notice saying
        # it was registered.
        dropped = _dropped_grant_types(
            metadata.get("grant_types", ["authorization_code"]), application.authorization_grant_type
        )
        if dropped:
            log.info(
                "CIMD client %r declares grant_types %r, which this server does not "
                "register; registering %r only",
                client_id,
                dropped,
                application.authorization_grant_type,
            )
        if previous_algorithm is not None and application.algorithm != previous_algorithm:
            log.info(
                "CIMD application %r ID Token signing algorithm changed from %r to %r on re-fetch",
                client_id,
                previous_algorithm,
                application.algorithm,
            )
        if (
            previous_auth_method is not None
            and application.token_endpoint_auth_method != previous_auth_method
        ):
            log.info(
                "CIMD application %r token_endpoint_auth_method changed from %r to %r on re-fetch",
                client_id,
                previous_auth_method,
                application.token_endpoint_auth_method,
            )
        elif (
            previous_keys is not None
            and (application.client_jwks, application.client_jwks_uri) != previous_keys
        ):
            log.info("CIMD application %r published new client keys on re-fetch", client_id)
    return application


def _backoff_cache_key(client_id):
    """Return the failure-backoff cache key for *client_id*.

    The client_id (untrusted, up to 255 chars) is hashed so the key can't exceed
    a cache backend's key-length limit (e.g. memcached's 250 bytes) and silently
    drop the backoff — or raise before the URL is ever validated.
    """
    digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
    return BACKOFF_CACHE_PREFIX + digest


def _policy_backoff_cache_key(client_id: str) -> str:
    """Return the policy-refusal backoff cache key for *client_id*.

    Distinct from :func:`_backoff_cache_key`: the key also carries a digest of
    this node's authentication-method policy (:func:`_supported_auth_methods`),
    so only nodes with the same policy share it, and a policy change yields a
    new key and takes effect on the next request. Both parts are hashed so the
    key stays within a cache backend's key-length limit.
    """
    client_digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
    policy = ",".join(sorted(_supported_auth_methods()))
    policy_digest = hashlib.sha256(policy.encode("utf-8")).hexdigest()
    return f"{BACKOFF_CACHE_PREFIX}policy:{client_digest}:{policy_digest}"


def resolve_cimd_application(client_id: str, request: Request) -> AbstractApplication | None:
    """Resolve a CIMD *client_id* URL to a persisted Application, or None.

    Returns None (the caller then treats the client as unknown) when CIMD is
    disabled, the id is not a CIMD URL, registration is refused by the
    permission classes or by this server's authentication-method policy, the
    URL is in failure or policy-refusal backoff, the in-flight cap is reached,
    or the document is missing or invalid. *request* is the oauthlib request
    the client_id arrived on; it is forwarded to the permission classes.
    """
    if not oauth2_settings.CIMD_ENABLED or not is_cimd_client_id(client_id):
        return None

    # Policy gate, checked before any fetch. A denial is not a fetch failure,
    # so it does not set the backoff: adding a host to the allowlist takes
    # effect on the very next request.
    if not _registration_permitted(request, client_id):
        log.info("CIMD registration refused by permission classes for %r", client_id)
        return None

    backoff_key = _backoff_cache_key(client_id)
    if cache.get(backoff_key):
        return None
    policy_backoff_key = _policy_backoff_cache_key(client_id)
    if cache.get(policy_backoff_key):
        return None

    with _fetch_slot() as acquired:
        if not acquired:
            # Not backed off: this URL may be perfectly fine, just over capacity.
            log.warning("CIMD fetch skipped for %r: in-flight cap reached", client_id)
            return None
        try:
            return _fetch_validate_upsert(client_id)
        except CIMDPolicyError as exc:
            # A policy refusal arms only the policy-scoped backoff, never the
            # shared one: refetches are bounded, yet it neither blocks nodes
            # whose policy accepts the document nor outlives a change to this
            # node's policy (which yields a different key).
            log.info("CIMD registration refused by server policy for %r: %r", client_id, exc)
            cache.set(policy_backoff_key, True, oauth2_settings.CIMD_FAILURE_BACKOFF_SECONDS)
            return None
        except CIMDError as exc:
            log.info("CIMD resolution failed for %r: %r", client_id, exc)
            cache.set(backoff_key, True, oauth2_settings.CIMD_FAILURE_BACKOFF_SECONDS)
            return None
        except Exception:
            # This runs on the pre-auth authorize/token endpoint against a
            # client-controlled URL, so an unexpected error must degrade to
            # "unknown client", never a 500. Back it off to stop cheap repeats.
            log.exception("Unexpected error resolving CIMD client %r", client_id)
            cache.set(backoff_key, True, oauth2_settings.CIMD_FAILURE_BACKOFF_SECONDS)
            return None


def refresh_if_stale(application, request):
    """Re-fetch a CIMD Application's metadata when its cache has expired.

    Returns the refreshed Application, or the original unchanged when it is not
    a CIMD application, is still fresh, or the re-fetch fails. Keeping the last
    good document on failure avoids locking a client out over a transient blip
    (the spec forbids caching an error as the authoritative result).
    """
    if (
        application.registration_source != application.RegistrationSource.CIMD
        or application.cimd_expires_at is None
    ):
        return application
    if timezone.now() <= application.cimd_expires_at:
        return application
    refreshed = resolve_cimd_application(application.client_id, request)
    return refreshed if refreshed is not None else application


def is_usable_registration(application: AbstractApplication) -> bool:
    """Return False for a CIMD Application this server would no longer register.

    The authentication-method policy (:func:`_supported_auth_methods`) is
    checked when a document is fetched, but a row stored earlier, or by another
    node, outlives it: a server that stops advertising ``private_key_jwt`` must
    not keep authenticating a client registered with it, and refetching cannot
    help, because the refetched document is refused by the same policy. This
    check refuses such a row at load time instead. The row itself is left
    untouched, so advertising the method again restores the client without a
    refetch. Non-CIMD applications are always usable here.
    """
    if application.registration_source != application.RegistrationSource.CIMD:
        return True
    # Rows stored before the method was recorded carry the blank default; every
    # one of them was public.
    method = application.token_endpoint_auth_method or application.TOKEN_AUTH_METHOD_NONE
    if method in _supported_auth_methods():
        return True
    log.info(
        "CIMD application %r is registered with token_endpoint_auth_method %r, "
        "which this server does not register; refusing it",
        application.client_id,
        method,
    )
    return False
