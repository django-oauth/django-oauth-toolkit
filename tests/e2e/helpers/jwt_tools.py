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


def validate_logout_token(token, issuer, audience):
    """Validate a Logout Token per *Back-Channel Logout 1.0 section 2.6*.

    Implements the steps an RP MUST perform, in the spec's own order, and returns the
    verified claims. Step 1 (decryption) does not apply -- DOT does not encrypt logout
    tokens -- and steps 8 to 11 are marked optional and depend on RP-side state, so
    only the parts observable from a single token are asserted here.
    """
    keyset, _ = fetch_jwks(issuer)
    header = decode_header(token)

    # Step 3: "an alg with the value none MUST NOT be used for Logout Tokens".
    assert header.get("alg"), "Logout Token has no alg header"
    assert header["alg"] != "none", "Logout Token signed with alg=none"

    # Step 2: validate the signature the way an ID Token's is validated -- against the
    # same JWKS, since section 2.4 requires the same keys.
    key = keyset.get_key(header["kid"])
    if key is None:
        raise AssertionError(f"Logout Token kid {header['kid']!r} not present in JWKS")
    verified = jwt.JWT(key=key, jwt=token)
    claims = json.loads(verified.claims)

    # Step 4: iss, aud, iat and exp, as for an ID Token.
    assert claims["iss"] == issuer, f"iss mismatch: {claims['iss']!r} != {issuer!r}"
    aud = claims["aud"]
    aud = aud if isinstance(aud, list) else [aud]
    assert audience in aud, f"aud {aud!r} does not contain {audience!r}"
    assert isinstance(claims.get("iat"), int), "Logout Token missing integer iat claim"
    assert isinstance(claims.get("exp"), int), "Logout Token missing integer exp claim"
    assert claims["exp"] > claims["iat"], "Logout Token exp is not after iat"
    assert claims["exp"] > int(time.time()), "Logout Token is already expired"

    # Step 5: a sub claim, a sid claim, or both.
    assert claims.get("sub") or claims.get("sid"), "Logout Token has neither sub nor sid"

    # Step 6: the events claim, carrying the backchannel-logout member name.
    events = claims.get("events")
    assert isinstance(events, dict), "Logout Token events claim is not a JSON object"
    event_name = "http://schemas.openid.net/event/backchannel-logout"
    assert event_name in events, f"Logout Token events claim lacks {event_name!r}"

    # Step 7: a nonce is prohibited, so that a Logout Token cannot pass as an ID Token.
    assert "nonce" not in claims, "Logout Token contains a prohibited nonce claim"

    # Step 8 needs more than one token to be meaningful, but a jti is REQUIRED by
    # section 2.4 and an RP cannot do replay detection without one.
    assert claims.get("jti"), "Logout Token missing jti claim"

    return claims
