"""
RFC 7523 JWT client authentication (private_key_jwt / client_secret_jwt).

Implements section 2.2 of RFC 7523 (with the processing rules of section 3
and RFC 7521 section 4.2): a client authenticates to the token, introspection
or revocation endpoint by posting ``client_assertion_type=urn:ietf:params:
oauth:client-assertion-type:jwt-bearer`` and a signed JWT ``client_assertion``
instead of a client secret.

Assertions are only accepted for applications explicitly registered with
``token_endpoint_auth_method`` ``private_key_jwt`` (verified against the
application's inline ``client_jwks`` or remote ``client_jwks_uri``) or
``client_secret_jwt`` (HMAC over the plaintext client secret). Every check
fails closed; a failed assertion surfaces to the client as a plain
``invalid_client`` error, exactly like a wrong secret.

The RFC 7523 section 2.1 authorization grant
(``urn:ietf:params:oauth:grant-type:jwt-bearer``) is intentionally not
implemented here.
"""

import hashlib
import json
import logging
import math
import numbers
import threading
import time
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from django.conf import settings as django_settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.http.request import split_domain_port, validate_host
from jwcrypto import jwk, jws, jwt
from jwcrypto.common import JWException

from oauth2_provider.core import safe_fetch
from oauth2_provider.core.rfc7523 import JWT_BEARER_CLIENT_ASSERTION_TYPE
from oauth2_provider.core.utils import jwk_allows_verification
from oauth2_provider.settings import oauth2_settings


if TYPE_CHECKING:
    from oauth2_provider.models import AbstractApplication


log = logging.getLogger(__name__)

REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "jti")

JWKS_CACHE_PREFIX = "oauth2_provider:client_jwks:"
JWKS_BACKOFF_CACHE_PREFIX = "oauth2_provider:client_jwks_backoff:"
JWKS_REFETCH_CACHE_PREFIX = "oauth2_provider:client_jwks_refetch:"
JTI_CACHE_PREFIX = "oauth2_provider:client_assertion_jti:"

# Upper bound for CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS: 30 days, the
# longest relative expiry memcached accepts. Larger timeouts are read as
# absolute timestamps by memcached, rejected by Redis once they overflow, and
# make LocMemCache raise OverflowError.
JWKS_REFETCH_INTERVAL_MAX_SECONDS = 30 * 24 * 60 * 60

# The invalid CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS values (by repr)
# already warned about. The setting is read on every unknown-kid assertion,
# which unauthenticated callers can send, so a misconfiguration is logged once
# per distinct value per process rather than once per request.
_refetch_interval_warnings: set[tuple[str, str]] = set()
_refetch_interval_warnings_lock = threading.Lock()


class ClientAssertionError(Exception):
    """A client assertion failed validation.

    The message is safe to log (it never contains the assertion itself) but is
    never returned to the client: every failure surfaces as ``invalid_client``.
    """


def authenticate_client_assertion(request, load_application):
    """Authenticate an oauthlib *request* carrying a JWT client assertion.

    *load_application* is the validator's ``_load_application`` (it sets
    ``request.client`` as a side effect). Returns True when the assertion
    verifies; False otherwise. Never raises.
    """
    try:
        _authenticate(request, load_application)
    except ClientAssertionError as error:
        log.debug("Failed client assertion authentication: %s", error)
        return False
    return True


def _authenticate(request, load_application):
    assertion_type = getattr(request, "client_assertion_type", None)
    assertion = getattr(request, "client_assertion", None)
    if assertion_type != JWT_BEARER_CLIENT_ASSERTION_TYPE:
        raise ClientAssertionError(f"unsupported client_assertion_type {assertion_type!r}")
    if not assertion:
        raise ClientAssertionError("missing client_assertion")
    # RFC 6749 section 2.3: a request MUST NOT use more than one client
    # authentication mechanism; RFC 7521 section 4.2 restates it for
    # assertions. Reject rather than pick one.
    authorization = request.headers.get("HTTP_AUTHORIZATION", "") or request.headers.get("Authorization", "")
    if authorization.split(" ", 1)[0].lower() == "basic":
        raise ClientAssertionError("client_assertion combined with HTTP Basic authentication")
    # Presence of the parameter is what matters, even with an empty value
    # (oauthlib maps an absent parameter to None, an empty one to "").
    if getattr(request, "client_secret", None) is not None:
        raise ClientAssertionError("client_assertion combined with a client_secret parameter")

    header, claims = _peek_assertion(assertion)
    for claim in REQUIRED_CLAIMS:
        if claim not in claims:
            raise ClientAssertionError(f"client assertion is missing the {claim!r} claim")
    client_id = claims["sub"]
    if not isinstance(client_id, str) or not client_id:
        raise ClientAssertionError("client assertion 'sub' claim is not a client_id")
    if claims["iss"] != client_id:
        raise ClientAssertionError("client assertion 'iss' and 'sub' claims differ")
    # RFC 7521 section 4.2: a client_id parameter, when present, must identify
    # the same client as the assertion. Presence-based like the client_secret
    # check above: an empty client_id= does not identify the same client.
    body_client_id = getattr(request, "client_id", None)
    if body_client_id is not None and body_client_id != client_id:
        raise ClientAssertionError("client_id parameter does not match the client assertion 'sub'")

    application = load_application(client_id, request)
    if application is None:
        raise ClientAssertionError(f"no application found for client_id {client_id!r}")
    request.client_id = client_id

    allowed_algs = _allowed_algs(application)
    alg = header.get("alg")
    if alg not in allowed_algs:
        raise ClientAssertionError(
            f"alg {alg!r} is not accepted for {application.token_endpoint_auth_method}"
        )

    verified_claims = _verify_signature(assertion, application, header, allowed_algs)
    _check_times(verified_claims)
    _check_audience(verified_claims["aud"], request)
    _check_jti_replay(client_id, verified_claims)
    return application


def _peek_assertion(assertion):
    """Parse the JOSE header and claims without verifying — fail closed on any
    malformation. Nothing peeked here is trusted until _verify_signature ran."""
    unverified = jws.JWS()
    try:
        unverified.deserialize(assertion)
        header = unverified.jose_header
        payload = unverified.objects["payload"]
        claims = json.loads(payload.decode("utf-8"))
    except (JWException, ValueError, KeyError, UnicodeDecodeError) as exc:
        raise ClientAssertionError(f"malformed client assertion: {exc.__class__.__name__}")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ClientAssertionError("malformed client assertion structure")
    return header, claims


def _allowed_algs(application):
    method = application.token_endpoint_auth_method
    if method == application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT:
        return list(oauth2_settings.CLIENT_ASSERTION_PRIVATE_KEY_JWT_ALGS)
    if method == application.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT:
        return list(oauth2_settings.CLIENT_ASSERTION_CLIENT_SECRET_JWT_ALGS)
    # Fail closed: assertions are opt-in per client. Applications registered
    # for secret-based methods (or with the legacy blank method) cannot present
    # assertions, mirroring how JWT-registered clients cannot present secrets.
    raise ClientAssertionError(
        f"application {application.client_id!r} is not registered for JWT client authentication"
    )


def _candidate_keys(application: "AbstractApplication", header: dict[str, Any]) -> list[jwk.JWK]:
    """Resolve the verification key candidates for *application*.

    For client_secret_jwt this is the oct key derived from the plaintext
    secret. For private_key_jwt it is the registered JWKS (inline or fetched
    from client_jwks_uri), narrowed by the assertion's ``kid`` when given; an
    unknown ``kid`` against a remote JWKS triggers a cache-bypassing refetch
    so freshly rotated keys are honored. That refetch runs before the
    signature is verified, on a ``kid`` the caller chooses, so it is limited
    to one per ``jwks_uri`` per ``CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS``
    (see :func:`_claim_forced_refetch`); otherwise, or when the refetch
    fails, the cached set is used.

    ``kid`` is a hint (RFC 7515 section 4.1.4), not a filter: when it matches
    nothing, every registered signing key is tried instead — the signature
    still has to verify against a registered key, so the fallback costs
    nothing security-wise and tolerates clients whose kid labels differ (e.g.
    a thumbprint-derived kid against a set registered with human-named kids).
    """
    if application.token_endpoint_auth_method == application.TOKEN_AUTH_METHOD_CLIENT_SECRET_JWT:
        try:
            return [application.get_client_secret_hmac_jwk()]
        except ImproperlyConfigured as exc:
            raise ClientAssertionError(str(exc))

    kid = header.get("kid")
    if application.client_jwks:
        try:
            key_set = application.get_client_signing_jwks()
        except (JWException, ValueError):
            raise ClientAssertionError("registered client_jwks could not be parsed")
        keys = _signing_keys(key_set, kid) or _signing_keys(key_set, None)
    elif application.client_jwks_uri:
        key_set, from_cache = _load_remote_jwks(application)
        keys = _signing_keys(key_set, kid)
        # A set that was just fetched is as fresh as a forced refetch would
        # be; only a cached set can be missing a recently rotated key.
        if not keys and kid and from_cache and _claim_forced_refetch(application.client_jwks_uri):
            try:
                key_set = fetch_remote_jwks(application, force=True)
            except ClientAssertionError as exc:
                # A failed refetch must not reject an assertion a cached key
                # verifies. The next forced refetch waits for the failure
                # backoff or the interval, whichever is longer.
                _release_forced_refetch(application.client_jwks_uri)
                log.debug("Forced client JWKS refetch failed, using the cached set: %s", exc)
            else:
                keys = _signing_keys(key_set, kid)
        if not keys:
            keys = _signing_keys(key_set, None)
    else:
        raise ClientAssertionError("application has no registered JWKS")
    if not keys:
        raise ClientAssertionError("no registered key matches the client assertion")
    return keys


def _claim_forced_refetch(uri: str) -> bool:
    """Atomically claim the right to a cache-bypassing refetch of *uri*.

    The claim is a per-URI marker held in the default Django cache for
    ``CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS``; ``cache.add`` only
    succeeds for the first caller, so at most one forced refetch per interval
    reaches the URL however many unknown-``kid`` assertions arrive. ``0`` or
    ``None`` disables forced refetches entirely. Deployments running multiple
    instances need a shared cache backend for the limit to be global.

    Nothing is claimed while the failure backoff for *uri* is armed: the
    fetch would be refused anyway, and a marker held without a fetch would
    delay recognizing a rotated key past the backoff. A backoff shorter than
    the interval would not make :func:`_release_forced_refetch` give such a
    marker back either.
    """
    interval = _refetch_interval()
    if interval is None:
        return False
    digest = hashlib.sha256(uri.encode()).hexdigest()
    if cache.get(JWKS_BACKOFF_CACHE_PREFIX + digest):
        return False
    return cache.add(JWKS_REFETCH_CACHE_PREFIX + digest, True, timeout=interval)


def _refetch_interval() -> int | None:
    """``CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS`` as whole seconds.

    Returns ``None`` when forced refetches are disabled. Accepted values are
    numbers (``int``, ``float``, ``Decimal`` and the like) and strings that
    ``int()`` parses (``"60"``, but not ``"60.0"``):

    * ``None`` and zero (``0``, ``0.0``, ``"0"``) disable refetches silently.
    * A whole number from 1 up is used, clamped to
      :data:`JWKS_REFETCH_INTERVAL_MAX_SECONDS` (30 days) with a warning.
    * A number with a fractional part is truncated with a warning, and
      disables refetches if that leaves less than 1: a timeout below one
      second would make some cache backends, memcached among them, expire
      the marker at once.
    * Anything else disables refetches with a warning: a negative value
      (which would disable the limit), a ``bool`` (``True`` is not a
      duration), ``inf``, ``nan``, any other string or other type.

    Each warning is logged once per distinct value and problem (see
    :func:`_warn_refetch_interval_once`).
    """
    value = oauth2_settings.CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS
    if value is None:
        return None
    interval = None
    fractional = False
    if isinstance(value, bool):
        pass  # bool is an int subclass, but True/False are not durations.
    elif isinstance(value, str):
        try:
            interval = int(value)
        except ValueError:
            pass  # not a whole-number string: interval stays None and is warned about below
    elif isinstance(value, numbers.Number):
        # Judge the magnitude before converting: this runs on unauthenticated
        # requests, and int() of an absurd Decimal such as Decimal("1e1000000")
        # takes seconds.
        too_large, negative = _interval_out_of_range(value)
        if too_large:
            interval = JWKS_REFETCH_INTERVAL_MAX_SECONDS + 1
        elif not negative:
            try:
                interval = int(value)
                fractional = interval != value
            except Exception:
                # complex, inf, nan, or a value whose conversion or comparison
                # raises: the token path must not raise, so treat it as invalid.
                interval = None
                fractional = False
    if interval is None or interval < 0 or (interval == 0 and fractional):
        _warn_refetch_interval_once(
            value,
            "Invalid CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS %s; it must be a positive "
            "whole number of seconds. Unknown-kid JWKS refetches are disabled.",
        )
        return None
    if interval == 0:
        return None
    if interval > JWKS_REFETCH_INTERVAL_MAX_SECONDS:
        _warn_refetch_interval_once(
            value,
            "CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS %s exceeds the maximum of "
            f"{JWKS_REFETCH_INTERVAL_MAX_SECONDS} seconds (30 days); using the maximum.",
        )
        return JWKS_REFETCH_INTERVAL_MAX_SECONDS
    if fractional:
        _warn_refetch_interval_once(
            value,
            "CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS %s is not a whole number of seconds; "
            f"using {interval}.",
        )
    return interval


def _interval_out_of_range(value: numbers.Number) -> tuple[bool, bool]:
    """Return ``(too_large, negative)`` for a numeric refetch interval, cheaply.

    A Decimal is not a ``numbers.Real``, so it gets its own branch, judged by
    its sign and exponent. Infinities and NaNs, of any numeric type (numpy
    scalars included), report neither, so that ``int()`` rejects them; so do
    complex numbers, which do not order, and any value whose comparison raises.
    """
    if isinstance(value, Decimal):
        if not value.is_finite() or value.is_zero():
            return False, False
        if value.is_signed():
            return False, True
        return value.adjusted() >= len(str(JWKS_REFETCH_INTERVAL_MAX_SECONDS)), False
    if not isinstance(value, numbers.Real):
        return False, False
    try:
        is_nan = math.isnan(value)
    except (TypeError, ValueError, OverflowError):
        is_nan = False  # too large for a float, or not convertible to one: not a NaN
    try:
        # Infinities and NaNs of any Real type, not only the builtin float.
        if is_nan or value == math.inf or value == -math.inf:
            return False, False
        return value > JWKS_REFETCH_INTERVAL_MAX_SECONDS, value < 0
    except Exception:
        return False, False


def _warn_refetch_interval_once(value: object, message: str) -> None:
    """Log *message* about the refetch interval *value*, once per value and message.

    *message* gets ``repr(value)`` as its only ``%s`` argument. The memo is
    keyed on the message as well as the value, so two different problems whose
    values render alike are both reported.
    """
    try:
        rendered = repr(value)
    except Exception:
        # An int with more digits than sys.get_int_max_str_digits() allows, or
        # a configuration object whose __repr__ raises: this runs on the
        # unauthenticated token path, which must never raise from here.
        rendered = f"<{type(value).__name__} that cannot be displayed>"
    key = (message, rendered)
    with _refetch_interval_warnings_lock:
        if key in _refetch_interval_warnings:
            return
        _refetch_interval_warnings.add(key)
    log.warning(message, rendered)


def _release_forced_refetch(uri: str) -> None:
    """Give back the forced-refetch marker for *uri* after a failed fetch.

    The marker is only released when the failure backoff the fetch armed
    lasts at least as long as the interval: the backoff then keeps the next
    forced refetch at least one interval away on its own, and holding the
    marker as well would only delay recognizing a rotated key beyond the
    backoff. With a shorter backoff (including ``0``, which arms none),
    releasing the marker would allow one forced refetch of a failing URL per
    backoff rather than per interval, so the marker is kept until the
    interval elapses. Either way a failing URL is force-fetched at most once
    per ``CLIENT_ASSERTION_JWKS_REFETCH_INTERVAL_SECONDS``.
    """
    interval = _refetch_interval()
    backoff = oauth2_settings.CLIENT_ASSERTION_JWKS_FAILURE_BACKOFF_SECONDS
    if interval is None or (backoff is not None and backoff < interval):
        return
    digest = hashlib.sha256(uri.encode()).hexdigest()
    if cache.get(JWKS_BACKOFF_CACHE_PREFIX + digest):
        cache.delete(JWKS_REFETCH_CACHE_PREFIX + digest)


def _signing_keys(key_set, kid):
    if kid is not None:
        key = key_set.get_key(kid)
        keys = [key] if key is not None else []
    else:
        keys = list(key_set["keys"])
    return [key for key in keys if _key_allows_verification(key) and not key.has_private]


# Shared with Application.clean(), which fails fast on key sets that could
# never verify an assertion.
_key_allows_verification = jwk_allows_verification


def _verify_signature(assertion, application, header, allowed_algs):
    """Verify the assertion against each candidate key; return the claims of
    the first key that validates the signature (and jwcrypto's exp/nbf checks).
    """
    keys = _candidate_keys(application, header)
    leeway = oauth2_settings.CLIENT_ASSERTION_LEEWAY
    for key in keys:
        token = jwt.JWT(algs=allowed_algs)
        token.leeway = leeway
        try:
            token.deserialize(assertion, key)
        except (JWException, ValueError):
            continue
        return json.loads(token.claims)
    raise ClientAssertionError("client assertion signature could not be verified")


def _check_times(claims):
    """Cap the assertion lifetime and sanity-check nbf/iat.

    jwcrypto already rejected an expired ``exp`` and a future ``nbf`` during
    deserialization; what's left is bounding how long-lived an assertion may
    be (RFC 7523 section 3 note on rejecting unreasonable lifetimes, limiting
    the replay window the jti cache must cover) and refusing future ``iat``.
    """
    now = time.time()
    leeway = oauth2_settings.CLIENT_ASSERTION_LEEWAY
    max_lifetime = oauth2_settings.CLIENT_ASSERTION_MAX_LIFETIME
    exp = claims["exp"]
    if not isinstance(exp, (int, float)):
        raise ClientAssertionError("client assertion 'exp' claim is not a number")
    if exp > now + max_lifetime + leeway:
        raise ClientAssertionError("client assertion expiration is unreasonably far in the future")
    iat = claims.get("iat")
    if iat is not None:
        if not isinstance(iat, (int, float)):
            raise ClientAssertionError("client assertion 'iat' claim is not a number")
        if iat > now + leeway:
            raise ClientAssertionError("client assertion was issued in the future")


def _check_audience(audience, request):
    audiences = audience if isinstance(audience, list) else [audience]
    accepted = _accepted_audiences(request)
    if not any(isinstance(aud, str) and _normalize_audience(aud) in accepted for aud in audiences):
        raise ClientAssertionError(f"client assertion audience {audiences!r} is not this server")


def _accepted_audiences(request):
    """The audience values this server answers to, normalized.

    ``CLIENT_ASSERTION_ACCEPTED_AUDIENCES`` is authoritative when set — the
    escape hatch for reverse proxies that rewrite the externally visible URL.
    Otherwise the accepted set is derived: the OIDC issuer (configured or
    request-derived) plus the URL of the endpoint the assertion was posted to.
    """
    # Any non-None value is authoritative — including an empty list, which
    # rejects every audience rather than silently falling back to derivation.
    configured = oauth2_settings.CLIENT_ASSERTION_ACCEPTED_AUDIENCES
    if configured is not None:
        return {_normalize_audience(audience) for audience in configured}
    accepted = set()
    try:
        accepted.add(_normalize_audience(oauth2_settings.oidc_issuer(request)))
    except Exception:
        # No OIDC urls installed (plain OAuth deployment) or a host Django
        # refuses; the request-URL audience below still applies.
        log.debug("Could not derive an issuer audience for client assertions", exc_info=True)
    host = _request_host(request.headers)
    if host and _host_is_allowed(host):
        scheme = "https" if request.headers.get("X_DJANGO_OAUTH_TOOLKIT_SECURE") else "http"
        path = urlparse(request.uri or "").path
        accepted.add(_normalize_audience(f"{scheme}://{host}{path}"))
    return accepted


def _host_is_allowed(host):
    """Validate *host* against ALLOWED_HOSTS before trusting it as an audience.

    The header is read straight from the oauthlib request, bypassing
    HttpRequest.get_host(), so an attacker could otherwise pick the derived
    audience with a crafted Host header. Mirrors get_host(): with DEBUG on and
    ALLOWED_HOSTS empty, the localhost variants are permitted.
    """
    allowed_hosts = django_settings.ALLOWED_HOSTS
    if django_settings.DEBUG and not allowed_hosts:
        allowed_hosts = [".localhost", "127.0.0.1", "[::1]"]
    domain, _port = split_domain_port(host)
    return bool(domain) and validate_host(domain, allowed_hosts)


def _request_host(headers):
    """The host the client addressed, following django.http.HttpRequest.get_host:
    the Host header when present, else SERVER_NAME[:SERVER_PORT]."""
    host = headers.get("HTTP_HOST") or headers.get("Host")
    if host:
        return host
    server_name = headers.get("SERVER_NAME")
    if not server_name:
        return None
    port = str(headers.get("SERVER_PORT") or "")
    if port and port not in ("80", "443"):
        return f"{server_name}:{port}"
    return server_name


def _normalize_audience(value):
    return value.rstrip("/")


def _check_jti_replay(client_id, claims):
    """Refuse an assertion whose jti was already seen (RFC 7523 section 3, bullet 7).

    The jti is remembered in the default Django cache until the assertion
    would have expired anyway. Both key components are hashed so a hostile
    jti cannot smuggle cache-key-invalid characters or unbounded length.
    Deployments running multiple instances need a shared cache backend for
    cross-instance replay protection (see docs).
    """
    jti = claims["jti"]
    if not isinstance(jti, str) or not jti:
        raise ClientAssertionError("client assertion 'jti' claim is not a string")
    timeout = claims["exp"] - time.time() + oauth2_settings.CLIENT_ASSERTION_LEEWAY
    if timeout <= 0:
        raise ClientAssertionError("client assertion is expired")
    digest = hashlib.sha256(f"{client_id}\x00{jti}".encode()).hexdigest()
    if not cache.add(JTI_CACHE_PREFIX + digest, True, timeout=int(timeout) + 1):
        raise ClientAssertionError("client assertion jti was replayed")


def fetch_remote_jwks(application: "AbstractApplication", *, force: bool = False) -> jwk.JWKSet:
    """Fetch and cache the JWK Set at *application.client_jwks_uri*.

    Returns a ``jwk.JWKSet`` holding only usable public signing keys. Results
    are cached for ``CLIENT_ASSERTION_JWKS_CACHE_TIMEOUT`` seconds; fetch or
    validation failures arm a short backoff so a broken URL is not hammered
    on every authentication attempt. ``force=True`` bypasses the value cache
    (for unknown-``kid`` refetches) but still honors the failure backoff;
    callers rate-limit it with :func:`_claim_forced_refetch`.
    """
    key_set, _from_cache = _load_remote_jwks(application, force=force)
    return key_set


def _load_remote_jwks(application: "AbstractApplication", *, force: bool = False) -> tuple[jwk.JWKSet, bool]:
    """Implement :func:`fetch_remote_jwks`, also reporting where the set came from.

    Returns ``(key_set, from_cache)``: ``from_cache`` is ``True`` when the set
    was served from the value cache and ``False`` when it was just fetched,
    which lets the unknown-``kid`` path skip a forced refetch that could only
    return the same document.
    """
    uri = application.client_jwks_uri
    digest = hashlib.sha256(uri.encode()).hexdigest()
    cache_key = JWKS_CACHE_PREFIX + digest
    backoff_key = JWKS_BACKOFF_CACHE_PREFIX + digest

    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            try:
                return jwk.JWKSet.from_json(cached), True
            except (JWException, ValueError):
                cache.delete(cache_key)
    if cache.get(backoff_key):
        raise ClientAssertionError("client jwks_uri is in failure backoff")

    try:
        data, _headers = safe_fetch.fetch_https_json(
            uri,
            timeout=oauth2_settings.CLIENT_ASSERTION_JWKS_FETCH_TIMEOUT_SECONDS,
            max_size=oauth2_settings.CLIENT_ASSERTION_JWKS_MAX_SIZE,
            exc_class=ClientAssertionError,
        )
        key_set = _build_public_jwks(data)
    except ClientAssertionError:
        cache.set(backoff_key, True, timeout=oauth2_settings.CLIENT_ASSERTION_JWKS_FAILURE_BACKOFF_SECONDS)
        raise
    cache.set(
        cache_key,
        key_set.export(private_keys=False),
        timeout=oauth2_settings.CLIENT_ASSERTION_JWKS_CACHE_TIMEOUT,
    )
    return key_set, False


def _build_public_jwks(data):
    entries = data.get("keys")
    if not isinstance(entries, list):
        raise ClientAssertionError("client jwks_uri document has no 'keys' list")
    key_set = jwk.JWKSet()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            key = jwk.JWK(**entry)
        except (JWException, ValueError, TypeError):
            log.debug("Skipping unparseable key in client JWKS")
            continue
        if key.has_private:
            # A client publishing private material is a client-side incident;
            # never store or use it.
            log.warning("Client JWKS contains private key material; skipping that key")
            continue
        if not _key_allows_verification(key):
            # Keep the cached set to what the docstring promises: keys usable
            # for signature verification (use=sig / key_ops with "verify").
            continue
        key_set.add(key)
    if not key_set["keys"]:
        raise ClientAssertionError("client jwks_uri document contains no usable public keys")
    return key_set


def token_endpoint_auth_signing_algs(auth_methods):
    """The JWS algs to advertise as ``*_auth_signing_alg_values_supported``
    for an endpoint whose ``*_auth_methods_supported`` is *auth_methods*.

    Empty when no JWT client authentication method is advertised, so callers
    can omit the metadata field entirely.
    """
    algs = []
    if "private_key_jwt" in auth_methods:
        algs.extend(oauth2_settings.CLIENT_ASSERTION_PRIVATE_KEY_JWT_ALGS)
    if "client_secret_jwt" in auth_methods:
        algs.extend(oauth2_settings.CLIENT_ASSERTION_CLIENT_SECRET_JWT_ALGS)
    return list(dict.fromkeys(algs))
