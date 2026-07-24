"""
Shared helpers for RFC 7521 / RFC 7523 JWT assertions.

This module holds the assertion machinery that is common to the two RFC 7523
profiles:

* §2.1 — the ``urn:ietf:params:oauth:grant-type:jwt-bearer`` *authorization*
  grant, where a JWT assertion is exchanged for an access token
  (implemented here, wired up in :mod:`oauth2_provider.oauth2_grants`); and
* §2.2 — JWT assertions used for *client authentication*
  (``private_key_jwt`` / ``client_secret_jwt``).

The functions are deliberately free of Django request/response types and take
their policy (leeway, accepted audiences, required claims, allowed algorithms)
as explicit arguments, so they can be reused by both profiles and unit-tested in
isolation. The only Django integration points are key loading from the
Application model / settings, the ``jti`` replay cache, and the default subject
resolver.

See RFC 7521 (https://www.rfc-editor.org/rfc/rfc7521) and RFC 7523
(https://www.rfc-editor.org/rfc/rfc7523).
"""

import json
import logging
import time
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from jwcrypto import jwk, jwt
from jwcrypto.common import JWException

from . import safe_fetch
from .settings import oauth2_settings


log = logging.getLogger(__name__)


# Asymmetric signature algorithms accepted for assertions by default. ``none``
# and the HMAC (``HS*``) family are intentionally excluded from the grant path:
# ``none`` is unsigned, and DOT stores client secrets hashed, so HMAC
# verification is not generally possible. RFC 7523 §3.1 leaves the acceptable
# algorithm set to server policy; override via the caller.
DEFAULT_ALLOWED_ALGS = [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
]

_JTI_CACHE_PREFIX = "oauth2_provider:jwt-assertion:jti:"
_JWKS_CACHE_PREFIX = "oauth2_provider:jwt-assertion:jwks:"


class JWTBearerAssertionError(Exception):
    """An assertion failed validation.

    Carries an OAuth 2.0 error code (RFC 6749 §5.2 / RFC 7521 §4.1.1) and a
    human-readable description suitable for the ``error_description`` field. The
    description is safe to return to the client — it never contains secrets.
    """

    def __init__(self, error, description):
        self.error = error
        self.description = description
        super().__init__(f"{error}: {description}")


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


def load_jwks(document):
    """Parse a JWK Set (RFC 7517) document string into a ``jwk.JWKSet``.

    Accepts either a JWK Set (a ``{"keys": [...]}`` object) or a single bare
    JWK, returning a ``JWKSet`` in both cases. Raises
    :class:`JWTBearerAssertionError` (``invalid_client``) on malformed input.
    """
    try:
        data = json.loads(document)
    except (ValueError, TypeError) as exc:
        raise JWTBearerAssertionError("invalid_client", "malformed JWK Set") from exc

    keyset = jwk.JWKSet()
    try:
        if isinstance(data, dict) and "keys" in data:
            keyset.import_keyset(document)
        else:
            keyset.add(jwk.JWK.from_json(document))
    except (JWException, ValueError, TypeError) as exc:
        raise JWTBearerAssertionError("invalid_client", "malformed JWK Set") from exc
    return keyset


def fetch_jwks(uri):
    """Fetch and cache the JWK Set at *uri*.

    The fetch is SSRF-hardened by the shared :mod:`oauth2_provider.safe_fetch`
    helper (https only, target IP resolved and validated as public before
    connecting, no redirects, bounded timeout and response size) — the same
    machinery used for CIMD and JWT client authentication. The document is
    cached for ``CLIENT_ASSERTION_JWKS_CACHE_TIMEOUT`` seconds.
    """
    cache_key = _JWKS_CACHE_PREFIX + uri
    cached = cache.get(cache_key)
    if cached is not None:
        return load_jwks(cached)

    try:
        data = safe_fetch.fetch_https_json(
            uri,
            timeout=oauth2_settings.CLIENT_ASSERTION_JWKS_FETCH_TIMEOUT_SECONDS,
            max_size=oauth2_settings.CLIENT_ASSERTION_JWKS_MAX_SIZE,
        )
    except safe_fetch.SafeFetchError as exc:
        raise JWTBearerAssertionError("invalid_client", "could not fetch JWK Set URI") from exc

    document = json.dumps(data)
    cache.set(cache_key, document, oauth2_settings.CLIENT_ASSERTION_JWKS_CACHE_TIMEOUT)
    return load_jwks(document)


def load_application_keys(application):
    """Return the ``jwk.JWKSet`` a client uses to sign JWTs, or ``None``.

    Prefers the inline ``client_jwks`` document; falls back to fetching
    ``client_jwks_uri``. Returns ``None`` when neither is configured.
    """
    inline = getattr(application, "client_jwks", "") or ""
    if inline.strip():
        return load_jwks(inline)
    uri = getattr(application, "client_jwks_uri", "") or ""
    if uri.strip():
        return fetch_jwks(uri)
    return None


def load_issuer_keys(issuer_config):
    """Return the ``jwk.JWKSet`` for a ``JWT_BEARER_TRUSTED_ISSUERS`` entry.

    The entry is a dict with either an inline ``jwks`` object or a ``jwks_uri``.
    """
    if not isinstance(issuer_config, dict):
        raise JWTBearerAssertionError("invalid_client", "malformed trusted-issuer configuration")
    if "jwks" in issuer_config and issuer_config["jwks"]:
        jwks = issuer_config["jwks"]
        return load_jwks(jwks if isinstance(jwks, str) else json.dumps(jwks))
    if issuer_config.get("jwks_uri"):
        return fetch_jwks(issuer_config["jwks_uri"])
    raise JWTBearerAssertionError("invalid_client", "trusted issuer has no keys configured")


# ---------------------------------------------------------------------------
# Verification and claim validation
# ---------------------------------------------------------------------------


def peek_unverified_claims(assertion):
    """Return the assertion's claims without verifying the signature.

    Used only to discover the ``iss`` so the right key material can be located;
    the assertion is fully verified afterwards. Raises
    :class:`JWTBearerAssertionError` (``invalid_grant``) if the token is not a
    well-formed JWS.
    """
    token = jwt.JWT()
    try:
        token.deserialize(assertion)
    except (JWException, ValueError, TypeError) as exc:
        raise JWTBearerAssertionError("invalid_grant", "assertion is not a well-formed JWT") from exc
    try:
        return json.loads(token.token.objects["payload"].decode("utf-8"))
    except (ValueError, KeyError, AttributeError) as exc:
        raise JWTBearerAssertionError("invalid_grant", "assertion payload is not valid JSON") from exc


def verify_assertion(assertion, keyset, *, allowed_algs=None):
    """Verify the assertion's signature against *keyset* and return its claims.

    Signature verification is enforced (``none`` is rejected); registered claim
    semantics are validated separately by :func:`validate_assertion_claims`, so
    ``exp``/``nbf`` are not checked here.
    """
    algs = list(allowed_algs) if allowed_algs is not None else list(DEFAULT_ALLOWED_ALGS)
    token = jwt.JWT(algs=algs, check_claims=False)
    try:
        token.deserialize(assertion, key=keyset)
    except (JWException, ValueError, TypeError) as exc:
        raise JWTBearerAssertionError("invalid_grant", "assertion signature verification failed") from exc
    try:
        return json.loads(token.claims)
    except (ValueError, TypeError) as exc:
        raise JWTBearerAssertionError("invalid_grant", "assertion payload is not valid JSON") from exc


def _as_timestamp(value, name):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise JWTBearerAssertionError("invalid_grant", f"assertion {name} claim is not a number")
    return int(value)


def validate_assertion_claims(
    claims,
    *,
    expected_audiences,
    require_jti=True,
    leeway=60,
    max_lifetime=None,
    now=None,
):
    """Validate the RFC 7523 §3 registered claims of a verified assertion.

    * ``iss``, ``sub``, ``aud`` and ``exp`` are REQUIRED.
    * ``exp`` must be in the future and ``nbf`` (if present) not in the future,
      both within *leeway* seconds of clock skew.
    * ``aud`` (a string or list) must intersect *expected_audiences*.
    * when *max_lifetime* is set, ``exp`` must not be further than that many
      seconds beyond *now* (bounds the replay window; §3).
    * when *require_jti* is true, ``jti`` is REQUIRED.

    Raises :class:`JWTBearerAssertionError` (``invalid_grant``) on any failure.
    """
    now = int(time.time()) if now is None else int(now)

    for required in ("iss", "sub", "aud", "exp"):
        if required not in claims:
            raise JWTBearerAssertionError("invalid_grant", f"assertion missing required claim: {required}")

    exp = _as_timestamp(claims["exp"], "exp")
    if exp <= now - leeway:
        raise JWTBearerAssertionError("invalid_grant", "assertion has expired")

    if "nbf" in claims:
        nbf = _as_timestamp(claims["nbf"], "nbf")
        if nbf > now + leeway:
            raise JWTBearerAssertionError("invalid_grant", "assertion is not yet valid")

    if max_lifetime is not None and exp - now > max_lifetime:
        raise JWTBearerAssertionError("invalid_grant", "assertion validity period is too long")

    audiences = claims["aud"]
    if isinstance(audiences, str):
        audiences = [audiences]
    if not isinstance(audiences, list) or not set(audiences) & set(expected_audiences):
        raise JWTBearerAssertionError("invalid_grant", "assertion audience does not match this server")

    if require_jti and not claims.get("jti"):
        raise JWTBearerAssertionError("invalid_grant", "assertion is missing the jti claim")


def check_and_record_jti(issuer, jti, exp, *, now=None, leeway=60):
    """Record ``(issuer, jti)`` to detect replay; raise if already seen.

    Uses the default Django cache (the same store JWT client authentication uses
    for its own replay guard). The entry lives until the assertion's ``exp``
    (plus *leeway*), after which the assertion is rejected as expired anyway, so
    nothing needs to remember it. Raises :class:`JWTBearerAssertionError`
    (``invalid_grant``) on replay. The grant keys the entry by ``iss`` (which may
    be a trusted third-party issuer, not the client), unlike the client-auth
    guard which keys by ``client_id``.

    .. note::
       Replay protection is only as strong as the configured cache. A
       per-process cache (e.g. LocMemCache) does not detect replays across
       worker processes; use a shared backend (Redis/memcached) in production.
    """
    now = int(time.time()) if now is None else int(now)
    # uuid5 keeps the cache key bounded and free of user-controlled characters
    # while remaining collision-free per (issuer, jti).
    digest = uuid.uuid5(uuid.NAMESPACE_OID, f"{issuer}\x00{jti}").hex
    cache_key = _JTI_CACHE_PREFIX + digest
    ttl = max(1, exp - now + leeway)
    if not cache.add(cache_key, "1", ttl):
        raise JWTBearerAssertionError("invalid_grant", "assertion has already been used (jti replay)")


# ---------------------------------------------------------------------------
# Subject resolution
# ---------------------------------------------------------------------------


def resolve_subject_by_username(claims, application, request):
    """Default ``JWT_BEARER_SUBJECT_RESOLVER``: map ``sub`` to a Django user.

    Looks the ``sub`` claim up against the user model's ``USERNAME_FIELD`` and
    returns the user only if it exists and is active; otherwise ``None`` (which
    the grant turns into ``invalid_grant``). Override the resolver setting to
    implement tenancy or per-client subject authorization policy.
    """
    UserModel = get_user_model()
    sub = claims.get("sub")
    if not sub:
        return None
    try:
        user = UserModel.objects.get(**{UserModel.USERNAME_FIELD: sub})
    except (UserModel.DoesNotExist, UserModel.MultipleObjectsReturned, ValueError, TypeError):
        return None
    if not getattr(user, "is_active", True):
        return None
    return user


# ---------------------------------------------------------------------------
# Client-side helper (library only)
# ---------------------------------------------------------------------------


def build_jwt_bearer_assertion(
    *,
    key,
    issuer,
    subject,
    audience,
    lifetime_seconds=300,
    algorithm="RS256",
    key_id=None,
    additional_claims=None,
):
    """Build and sign an RFC 7523 §2.1 grant assertion, returning the compact JWT.

    :param key: a ``jwcrypto.jwk.JWK`` private key to sign with.
    :param issuer: the ``iss`` claim (the client acting as issuer, or an STS).
    :param subject: the ``sub`` claim (the principal the token is requested for).
    :param audience: the ``aud`` claim (the authorization server's token
        endpoint URL or issuer identifier).
    :param lifetime_seconds: seconds until ``exp`` (``iat`` is set to now).
    :param algorithm: JWS ``alg`` header value.
    :param key_id: optional ``kid`` header; taken from *key* when omitted.
    :param additional_claims: extra claims merged into the payload.

    This is a convenience for building service-to-service clients and tests; it
    performs no network I/O.
    """
    issued_at = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": issued_at,
        "exp": issued_at + lifetime_seconds,
        "jti": uuid.uuid4().hex,
    }
    if additional_claims:
        claims.update(additional_claims)

    header = {"alg": algorithm}
    kid = key_id or key.get("kid")
    if kid:
        header["kid"] = kid

    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()
