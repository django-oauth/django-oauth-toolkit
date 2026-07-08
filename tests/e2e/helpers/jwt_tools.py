"""
Helpers for validating OpenID Connect ID Tokens against the IdP's published
JWKS, expressed in the language of *OpenID Connect Core 1.0 section 3.1.3.7
(ID Token Validation)*.
"""

import base64
import json
import time

import requests
from jwcrypto import jwk, jwt


def b64url_json(segment):
    """Decode a base64url JWT segment into a dict (no signature check)."""
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def decode_header(token):
    return b64url_json(token.split(".")[0])


def decode_claims_unverified(token):
    return b64url_json(token.split(".")[1])


def fetch_jwks(issuer):
    """Fetch the JWKS document and return a ``jwcrypto`` key set."""
    resp = requests.get(f"{issuer}/.well-known/jwks.json", timeout=5)
    resp.raise_for_status()
    return jwk.JWKSet.from_json(resp.text), resp.json()


def validate_id_token(token, issuer, audience):
    """Validate signature + ``iss``/``aud``/``exp`` per OIDC Core 3.1.3.7.

    Returns the verified claims dict. Raises on any validation failure.
    """
    keyset, _ = fetch_jwks(issuer)
    header = decode_header(token)
    key = keyset.get_key(header["kid"])
    if key is None:
        raise AssertionError(f"ID Token kid {header['kid']!r} not present in JWKS")
    # jwcrypto validates exp/nbf on construction; assert explicitly as well so
    # this compliance helper fails loudly on a missing or past exp claim.
    verified = jwt.JWT(key=key, jwt=token)
    claims = json.loads(verified.claims)
    assert claims["iss"] == issuer, f"iss mismatch: {claims['iss']!r} != {issuer!r}"
    aud = claims["aud"]
    aud = aud if isinstance(aud, list) else [aud]
    assert audience in aud, f"aud {aud!r} does not contain {audience!r}"
    assert "exp" in claims, "ID Token missing exp claim"
    assert claims["exp"] > int(time.time()), "ID Token is expired (exp in the past)"
    return claims
