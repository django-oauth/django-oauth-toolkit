"""Seed ``tests/app/idp`` for the OpenID Foundation conformance suite.

Runs inside the IdP container (the ``idp-seed`` service in docker-compose.yml)
once migrations have been applied. It creates the end-user the suite's built-in
browser logs in as, and the two statically registered clients the
``[client_registration=static_client]`` plans expect, with the suite's callback
and post-logout URIs for the ``dot`` alias used by ``config/dot-oidcc.json``.

Idempotent, so the stack can be brought up repeatedly against the same volume.
The credentials below are test fixtures for a throwaway container, not secrets.
"""

import os

import django


# The suite's test endpoints live under /test/a/<alias>/ on its public base URL.
SUITE_ALIAS_BASE = "https://localhost.emobix.co.uk:8443/test/a/dot"
# The second URI, with a query component, is what the suite's redirect-URI
# matching modules use.
REDIRECT_URIS = [
    f"{SUITE_ALIAS_BASE}/callback",
    f"{SUITE_ALIAS_BASE}/callback?dummy1=lorem&dummy2=ipsum",
]
POST_LOGOUT_REDIRECT_URIS = [f"{SUITE_ALIAS_BASE}/post_logout_redirect"]

USERNAME = "conformance"
PASSWORD = "conformance-password"

# One pair of clients per authorization grant type: an Application serves exactly
# one grant type, and the Basic, Implicit and Hybrid plans each need the matching
# one. (client_id, client_secret) per pair; the ids are what config/generate.py
# puts in the "client" / "client2" blocks of the static-client configurations.
CLIENTS_BY_GRANT = {
    "authorization-code": [
        ("openid-conformance-suite-client-1", "openid-conformance-suite-secret-1"),
        ("openid-conformance-suite-client-2", "openid-conformance-suite-secret-2"),
    ],
    "implicit": [
        ("openid-conformance-suite-implicit-1", "openid-conformance-suite-implicit-secret-1"),
        ("openid-conformance-suite-implicit-2", "openid-conformance-suite-implicit-secret-2"),
    ],
    "openid-hybrid": [
        ("openid-conformance-suite-hybrid-1", "openid-conformance-suite-hybrid-secret-1"),
        ("openid-conformance-suite-hybrid-2", "openid-conformance-suite-hybrid-secret-2"),
    ],
}


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "idp.settings")
    django.setup()

    from django.contrib.auth import get_user_model

    from oauth2_provider.models import get_application_model

    user_model = get_user_model()
    user, _ = user_model.objects.get_or_create(username=USERNAME)
    # Standard-claim sources for the profile/email scopes (see idp.oauth.CustomOAuth2Validator).
    user.first_name = "Conformance"
    user.last_name = "Tester"
    user.email = "conformance@example.com"
    user.set_password(PASSWORD)
    user.save()

    application_model = get_application_model()
    count = 0
    for grant_type, clients in CLIENTS_BY_GRANT.items():
        for index, (client_id, client_secret) in enumerate(clients, start=1):
            application_model.objects.update_or_create(
                client_id=client_id,
                defaults={
                    "user": user,
                    "name": f"OpenID Conformance Suite {grant_type} client {index}",
                    "client_type": application_model.CLIENT_CONFIDENTIAL,
                    "authorization_grant_type": grant_type,
                    "client_secret": client_secret,
                    "algorithm": application_model.RS256_ALGORITHM,
                    "redirect_uris": " ".join(REDIRECT_URIS),
                    "post_logout_redirect_uris": " ".join(POST_LOGOUT_REDIRECT_URIS),
                },
            )
            count += 1
    print(f"Seeded user {USERNAME!r} and {count} conformance clients.")


if __name__ == "__main__":
    main()
