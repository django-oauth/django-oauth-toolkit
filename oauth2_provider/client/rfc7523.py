"""Building RFC 7523 §2.1 JWT bearer grant assertions (relying-party side).

The mirror image of :mod:`oauth2_provider.authorization_server.rfc7523`: that
module *verifies* an assertion presented to this authorization server, while this
one *builds* one to present to some authorization server, which may well not be
this one. Keeping the two apart means a client can sign grant assertions without
pulling in any provider-side machinery — nothing here touches the app registry or
a model, and it performs no network I/O.

See :rfc:`7523#section-2.1` for the assertion grant.
"""

import time
import uuid

from jwcrypto import jwt


__all__ = ["build_jwt_bearer_assertion"]


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
