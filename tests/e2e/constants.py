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
