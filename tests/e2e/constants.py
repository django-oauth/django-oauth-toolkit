"""
Shared constants for the end-to-end / compliance suite.

The client applications and users referenced here are created by the fixtures
loaded into the live IdP:

* ``tests/app/idp/fixtures/seed.json`` — the shipped demo clients (the SvelteKit
  RP's OIDC Authorization Code client and the Device Authorization client).
* ``tests/app/idp/fixtures/e2e_seed.json`` — additional clients (one per grant
  type) and a claims-rich user, added specifically so the compliance suite can
  exercise every supported flow.

Keeping the identifiers in one place lets the spec test modules read as
declarations of *which client exercises which specification*.
"""

# --- Users -----------------------------------------------------------------
# Superuser from the shipped seed data.
SUPERUSER_USERNAME = "superuser"
SUPERUSER_PASSWORD = "password"

# Claims-rich end user from e2e_seed.json (has email + names for OIDC claims).
E2E_USERNAME = "e2euser"
E2E_PASSWORD = "e2epassword"
E2E_EMAIL = "e2e@example.com"
E2E_GIVEN_NAME = "Test"
E2E_FAMILY_NAME = "User"

# --- Client applications (e2e_seed.json) -----------------------------------
CONFIDENTIAL_CODE_CLIENT_ID = "e2e-confidential-code"
CONFIDENTIAL_CODE_SECRET = "confidential-code-secret"

PUBLIC_PKCE_CLIENT_ID = "e2e-public-pkce"

CLIENT_CREDENTIALS_CLIENT_ID = "e2e-client-credentials"
CLIENT_CREDENTIALS_SECRET = "client-credentials-secret"

PASSWORD_CLIENT_ID = "e2e-password"
PASSWORD_SECRET = "password-secret"

IMPLICIT_CLIENT_ID = "e2e-implicit"

HYBRID_CLIENT_ID = "e2e-hybrid"
HYBRID_SECRET = "hybrid-secret"

# RFC 7523 §2.1 JWT bearer grant. The public half of this key is registered on
# the "e2e-jwt-bearer" application (fixtures/e2e_seed.json) as client_jwks; the
# private half signs assertions in the test. Test-only key — never reuse.
JWT_BEARER_CLIENT_ID = "e2e-jwt-bearer"
JWT_BEARER_PRIVATE_JWK = {
    "kty": "RSA",
    "kid": "e2e-jwt-bearer-1",
    "e": "AQAB",
    "n": "1SIdxiZUn78-q-oEOVY3N0gaq0xyRar5ChXyaqSmxTVN9oOdTtAYSCky4EwPhyYB_UE_M2b2degMhQuQhegaezf3iAxOqq6ncxU1zk3-h-rAcjY8Tv70XqvxDGmuwhE9c-i3l8pU0eS5PBee84wNi-Kf8ham2D8EHP16J58QlKkyoLHnO-muqAaD9dUH2I8dmTvfFP2cZgOzkjlFm37xrYnq6-pIDqhxD3-jRz8nnYM405Jdul7ZhAZhKZfr2pc9EZvzSeT6EYQUPl3BAq5zIiGhk9S3sNIN5qCtCoaeDTFrxq_SnNJejW2cLphcWwuPmK4fwlG__yEt8s8U8lXpHQ",  # noqa: E501
    "d": "IRarVax0vdpEgg8SOc6TQu9cSJTVNtCs2i5_FKRcSciVQny7atVut6FBx0W3sW0qqOU8yR-miraMXwllFgzrM48ETGhQvDniQEEeOdms9u_wkaqu4Tq-uIXsJdewbGudxUVvX07nrTBbu6MVJ81p-vojh8ORgogB_PgzQzx0KAf2AWhKm25QaoiZ9G3xnCjv-c-nwUGuYDTo1A34xcdXMpTKkZfzrYPu72ZRx1BJf6udiOgzNAIQ38BFdo6BEvyBX1TxFrHgAZS5BJ3uCKvpi7T8oDY9gCHMjbJkRDsgXCd4oD2rTsbR71_yPExeRXiBvb-HGiLsy91F8b0giwcR5w",  # noqa: E501
    "p": "8tSKQcGYlKD8rSEWA3m8CDvBpqnG7-x9iY-oYOUTIyuXdfJ5jegjwLCRBaPP0UwACzKJJLhSTkFhC_lPygnRnv2bpsKOVPpBpCk6vHnCBe-XnZoklklQ44eJUbJF9uIpBpt50wFokyYbkH4YaTJQbGbCJqdslUjub0tG81lkd18",  # noqa: E501
    "q": "4LFDT3wUfijHYHkjQdxzseXPBg-3qHBvDYqUF9vFCmFJ2YU4r9kOvFbMd8fKcx29rBmWuZzoZzwGXE0HajQrEekeeAqEFJryNazr5hzb0Jr0ykn0bK0uJG7-jI5zsI8DmFDOePjlQQN1rvCoWA77_z8GG0HEpeR0cdzoreQVXQM",  # noqa: E501
    "dp": "oyREFtV4KzLVT4ORBJi-yVFMUypxKzPZS5gmaaK9br2UrntPSxWRH54AcKeTsWu8A8nZ9b-YHFc0WhUPlA9ws75y2mCPu2u-ugmxGns67T4AwLOUrRtoqtSeXzLEao-bPIMsH6Usmt_ZWQQ-Zj6VZZ7MBagp_UnYVxFeA5QlOUU",  # noqa: E501
    "dq": "DQ4_uv6asjnsW86uHcWRc2THArMnGMJvsXm74ScD6_Z7NAhpos4Z7ReeCdeyC75OpxFVkLNtTZJPTE2tgJ5HYmMJQjBaPFhEepnxmw1SOGzIjHh_m1D0vWk1oTUlw7yLmO4ZES5lI8HvtJqHLZaxTcN7t1m682iy22ramkAGfcE",  # noqa: E501
    "qi": "xaedlWOjxfCxF0-yVO1CIqRDkeqsaF6ExUkqDCPzFT5juYpuiw3JFMe-JBCWrtV-2H6MkBZb0V35wznFJzh92A12VRgfXoji6HjczpzCeinQ_AIubbb9XWM_UYe6YFrRt54wslJJT8T2D90EaWPvMXZUk4GO4fVik_E9tIWYzjQ",  # noqa: E501
}
JWT_BEARER_SUBJECT = E2E_USERNAME

# Shipped demo clients (seed.json).
RP_OIDC_CLIENT_ID = "2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm"
DEVICE_CLIENT_ID = "Qg8AaxKLs1c2W3PR70Sv5QxuSEREicKUlf83iGX3"

# Registered redirect URI shared by the redirect-based e2e clients. Nothing
# listens there; the RP client reads the authorization response from the 302
# ``Location`` header without following it.
REDIRECT_URI = "http://localhost:9000/callback"
POST_LOGOUT_REDIRECT_URI = "http://localhost:9000/logout-callback"

# --- Scope configuration handed to the IdP at launch -----------------------
# django-environ dict form (key=value pairs). Descriptions must not contain
# commas (the delimiter).
E2E_SCOPES = {
    "openid": "OpenID Connect scope",
    "read": "Read scope",
    "write": "Write scope",
    "email": "Email scope",
    "profile": "Profile scope",
    "introspection": "Introspect tokens scope",
}
E2E_DEFAULT_SCOPES = ["openid"]

# The public client that PKCE is *required* for; all other clients keep PKCE
# optional so the non-PKCE flows can be exercised against the same IdP.
PKCE_REQUIRED_CLIENT_IDS = [PUBLIC_PKCE_CLIENT_ID]
