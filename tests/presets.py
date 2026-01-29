from copy import deepcopy

from django.conf import settings


# A set of OAUTH2_PROVIDER settings dicts that can be used in tests

DEFAULT_SCOPES_RW = {"DEFAULT_SCOPES": ["read", "write"]}
DEFAULT_SCOPES_RO = {"DEFAULT_SCOPES": ["read"]}
OIDC_SETTINGS_RW = {
    "OIDC_ENABLED": True,
    "OIDC_ISS_ENDPOINT": "http://localhost/o",
    "OIDC_USERINFO_ENDPOINT": "http://localhost/o/userinfo/",
    "OIDC_RSA_PRIVATE_KEY": settings.OIDC_RSA_PRIVATE_KEY,
    "OIDC_RSA_PRIVATE_KEYS_INACTIVE": settings.OIDC_RSA_PRIVATE_KEYS_INACTIVE,
    "SCOPES": {
        "read": "Reading scope",
        "write": "Writing scope",
        "openid": "OpenID connect",
    },
    "DEFAULT_SCOPES": ["read", "write"],
    "PKCE_REQUIRED": False,
    "REFRESH_TOKEN_EXPIRE_SECONDS": 3600,
}
OIDC_SETTINGS_RO = deepcopy(OIDC_SETTINGS_RW)
OIDC_SETTINGS_RO["DEFAULT_SCOPES"] = ["read"]
OIDC_SETTINGS_EMAIL_SCOPE = deepcopy(OIDC_SETTINGS_RW)
OIDC_SETTINGS_EMAIL_SCOPE["SCOPES"].update({"email": "return email address"})
OIDC_SETTINGS_HS256_ONLY = deepcopy(OIDC_SETTINGS_RW)
del OIDC_SETTINGS_HS256_ONLY["OIDC_RSA_PRIVATE_KEY"]
OIDC_SETTINGS_RP_LOGOUT = deepcopy(OIDC_SETTINGS_RW)
OIDC_SETTINGS_RP_LOGOUT["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = True
OIDC_SETTINGS_RP_LOGOUT["OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT"] = False
OIDC_SETTINGS_RP_LOGOUT_STRICT_REDIRECT_URI = deepcopy(OIDC_SETTINGS_RP_LOGOUT)
OIDC_SETTINGS_RP_LOGOUT_STRICT_REDIRECT_URI["OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS"] = True
OIDC_SETTINGS_RP_LOGOUT_DENY_EXPIRED = deepcopy(OIDC_SETTINGS_RP_LOGOUT)
OIDC_SETTINGS_RP_LOGOUT_DENY_EXPIRED["OIDC_RP_INITIATED_LOGOUT_ACCEPT_EXPIRED_TOKENS"] = False
OIDC_SETTINGS_RP_LOGOUT_KEEP_TOKENS = deepcopy(OIDC_SETTINGS_RP_LOGOUT)
OIDC_SETTINGS_RP_LOGOUT_KEEP_TOKENS["OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS"] = False
REST_FRAMEWORK_SCOPES = {
    "SCOPES": {
        "read": "Read scope",
        "write": "Write scope",
        "scope1": "Scope 1",
        "scope2": "Scope 2",
        "resource1": "Resource 1",
    },
}
INTROSPECTION_SETTINGS = {
    "SCOPES": {
        "read": "Read scope",
        "write": "Write scope",
        "introspection": "Introspection scope",
        "dolphin": "eek eek eek scope",
    },
    "RESOURCE_SERVER_INTROSPECTION_URL": "http://example.org/introspection",
    "READ_SCOPE": "read",
    "WRITE_SCOPE": "write",
}

ALLOWED_SCHEMES_DEFAULT = {
    "ALLOWED_SCHEMES": ["https"],
}

ALLOWED_SCHEMES_HTTP = {
    "ALLOWED_SCHEMES": ["https", "http"],
}
