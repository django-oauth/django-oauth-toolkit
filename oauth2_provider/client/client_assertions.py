"""Building RFC 7523 client authentication assertions (relying-party side).

The mirror image of
:mod:`oauth2_provider.authorization_server.client_assertions`: that module
*verifies* an assertion presented to this authorization server, while this one
*builds* one to present to some authorization server, which may well not be this
one. Keeping the two apart means a client can sign assertions without pulling in
any provider-side machinery — nothing here touches the app registry or a model.

See :rfc:`7523#section-2.2` for the assertion format.
"""

import secrets
import time

from jwcrypto import jwk, jwt
from jwcrypto.common import base64url_encode

from oauth2_provider.core.utils import jwk_from_pem


__all__ = ["make_client_assertion"]

# jwk.JWK curve name -> JWS alg, for make_client_assertion's alg inference.
_EC_CURVE_ALGS = {"P-256": "ES256", "P-384": "ES384", "P-521": "ES512"}


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
