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
import secrets
import time
from urllib.parse import urlparse

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from jwcrypto import jwk, jws, jwt
from jwcrypto.common import JWException, base64url_encode

from . import safe_fetch
from .settings import oauth2_settings
from .utils import jwk_from_pem


log = logging.getLogger(__name__)

JWT_BEARER_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "jti")

JWKS_CACHE_PREFIX = "oauth2_provider:client_jwks:"
JWKS_BACKOFF_CACHE_PREFIX = "oauth2_provider:client_jwks_backoff:"
JTI_CACHE_PREFIX = "oauth2_provider:client_assertion_jti:"

# jwk.JWK curve name -> JWS alg, for make_client_assertion's alg inference.
_EC_CURVE_ALGS = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


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
    if getattr(request, "client_secret", None):
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
    # the same client as the assertion.
    body_client_id = getattr(request, "client_id", None)
    if body_client_id and body_client_id != client_id:
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


def _candidate_keys(application, header):
    """Resolve the verification key candidates for *application*.

    For client_secret_jwt this is the oct key derived from the plaintext
    secret. For private_key_jwt it is the registered JWKS (inline or fetched
    from client_jwks_uri), narrowed by the assertion's ``kid`` when given; an
    unknown ``kid`` against a remote JWKS triggers exactly one cache-bypassing
    refetch so freshly rotated keys are honored without hammering the URL.
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
        keys = _signing_keys(key_set, kid)
    elif application.client_jwks_uri:
        key_set = fetch_remote_jwks(application)
        keys = _signing_keys(key_set, kid)
        if not keys and kid:
            key_set = fetch_remote_jwks(application, force=True)
            keys = _signing_keys(key_set, kid)
    else:
        raise ClientAssertionError("application has no registered JWKS")
    if not keys:
        raise ClientAssertionError("no registered key matches the client assertion")
    return keys


def _signing_keys(key_set, kid):
    if kid is not None:
        key = key_set.get_key(kid)
        keys = [key] if key is not None else []
    else:
        keys = list(key_set["keys"])
    return [key for key in keys if key.get("use", "sig") == "sig" and not key.has_private]


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
    configured = oauth2_settings.CLIENT_ASSERTION_ACCEPTED_AUDIENCES
    if configured:
        return {_normalize_audience(audience) for audience in configured}
    accepted = set()
    try:
        accepted.add(_normalize_audience(oauth2_settings.oidc_issuer(request)))
    except Exception:
        # No OIDC urls installed (plain OAuth deployment) or a host Django
        # refuses; the request-URL audience below still applies.
        log.debug("Could not derive an issuer audience for client assertions", exc_info=True)
    host = _request_host(request.headers)
    if host:
        scheme = "https" if request.headers.get("X_DJANGO_OAUTH_TOOLKIT_SECURE") else "http"
        path = urlparse(request.uri or "").path
        accepted.add(_normalize_audience(f"{scheme}://{host}{path}"))
    return accepted


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


def fetch_remote_jwks(application, *, force=False):
    """Fetch and cache the JWK Set at *application.client_jwks_uri*.

    Returns a ``jwk.JWKSet`` holding only usable public signing keys. Results
    are cached for ``CLIENT_ASSERTION_JWKS_CACHE_TIMEOUT`` seconds; fetch or
    validation failures arm a short backoff so a broken URL is not hammered
    on every authentication attempt. ``force=True`` bypasses the value cache
    (for unknown-``kid`` refetches) but still honors the failure backoff.
    """
    uri = application.client_jwks_uri
    digest = hashlib.sha256(uri.encode()).hexdigest()
    cache_key = JWKS_CACHE_PREFIX + digest
    backoff_key = JWKS_BACKOFF_CACHE_PREFIX + digest

    if not force:
        cached = cache.get(cache_key)
        if cached is not None:
            try:
                return jwk.JWKSet.from_json(cached)
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
    return key_set


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


def make_client_assertion(client_id, key, audience, *, alg=None, lifetime=60, kid=None, extra_claims=None):
    """Create a signed RFC 7523 client authentication assertion (RP side).

    ``key`` may be a ``jwcrypto.jwk.JWK``, a private-key PEM (``str``/``bytes``),
    a JWK JSON string, or — for the HS* algorithms — the raw client secret.
    ``alg`` is inferred from the key type when omitted (RSA→RS256, EC→ES256/
    384/512 by curve, oct→HS256). ``audience`` is the token endpoint URL or
    issuer of the server the assertion is for (string or list).

    Returns the compact-serialized JWT. Each call generates a fresh ``jti``;
    make a new assertion per request instead of reusing one.
    """
    key = _as_signing_jwk(key, alg)
    if alg is None:
        alg = _infer_alg(key)
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": secrets.token_urlsafe(32),
        "iat": now,
        "nbf": now,
        "exp": now + lifetime,
    }
    if extra_claims:
        claims.update(extra_claims)
    header = {"alg": alg, "typ": "JWT"}
    kid = kid or key.get("kid")
    if kid:
        header["kid"] = kid
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def _as_signing_jwk(key, alg):
    if isinstance(key, jwk.JWK):
        return key
    if isinstance(key, bytes):
        key = key.decode("utf-8")
    if not isinstance(key, str):
        raise TypeError("key must be a jwk.JWK, a PEM/JWK-JSON string, or a raw HS* secret")
    stripped = key.strip()
    if stripped.startswith("{"):
        return jwk.JWK.from_json(stripped)
    if "-----BEGIN" in stripped:
        return jwk_from_pem(key)
    if alg is None or not alg.startswith("HS"):
        raise ValueError("a raw secret string requires an explicit HS* alg")
    return jwk.JWK(kty="oct", k=base64url_encode(key))


def _infer_alg(key):
    kty = key.get("kty")
    if kty == "RSA":
        return "RS256"
    if kty == "EC":
        curve_alg = _EC_CURVE_ALGS.get(key.get("crv"))
        if curve_alg:
            return curve_alg
    if kty == "oct":
        return "HS256"
    raise ValueError(f"cannot infer a JWS alg for key type {kty!r}; pass alg explicitly")
