"""Generate the suite configuration files in this directory.

The two files differ only in the ``alias`` (the suite's per-configuration
namespace, which decides the callback URIs) and in how the clients are
registered: ``dot-oidcc.json`` names the two clients ``seed_idp.py`` creates,
for the ``[client_registration=static_client]`` plans; ``dot-oidcc-dcr.json``
only names the clients, for the ``[client_registration=dynamic_client]`` plans,
where the suite registers them itself through the RFC 7591 endpoint.

Everything else, in particular the browser automation for the Django login,
consent and logout pages, is shared, so edit this script and re-run it rather
than the JSON::

    python tests/openid-conformance-suite/config/generate.py
"""

import json
from pathlib import Path


HERE = Path(__file__).resolve().parent

IDP = "https://dot-idp"
AUTHORIZE = f"{IDP}/o/authorize/*"
LOGIN = f"{IDP}/accounts/login/*"
LOGOUT = f"{IDP}/o/logout/*"

# Must match seed_idp.py.
USERNAME = "conformance"
PASSWORD = "conformance-password"
STATIC_CLIENTS = [
    {"client_id": "openid-conformance-suite-client-1", "client_secret": "openid-conformance-suite-secret-1"},
    {"client_id": "openid-conformance-suite-client-2", "client_secret": "openid-conformance-suite-secret-2"},
]
DCR_CLIENTS = [
    {"client_name": "openid-conformance-suite-client-1"},
    {"client_name": "openid-conformance-suite-client-2"},
]


def login_task(screenshot=False):
    commands = []
    if screenshot:
        # Fills the module's screenshot placeholder with the login page, which is
        # how the prompt=login / max_age modules prove the End-User was re-prompted.
        commands.append(["wait", "xpath", "//*", 10, "Log In", "update-image-placeholder-optional"])
    commands += [
        ["text", "id", "id_username", USERNAME],
        ["text", "id", "id_password", PASSWORD],
        ["click", "css", "button[type='submit']"],
    ]
    return {"task": "Login", "optional": True, "match": LOGIN, "commands": commands}


CONSENT = {
    "task": "Consent",
    "optional": True,
    "match": AUTHORIZE,
    "commands": [["click", "css", "input[name='allow']"]],
}
VERIFY_CALLBACK = {
    "task": "Verify Complete",
    "match": "*/test/*/callback*",
    "commands": [["wait", "id", "submission_complete", 10]],
}


def authorize_block(screenshot=False, comment=None):
    block = {"match": AUTHORIZE, "tasks": [login_task(screenshot), CONSENT, VERIFY_CALLBACK]}
    if comment:
        block = {"comment": comment, **block}
    return block


def error_page_block(match, comment):
    # Fatal errors are rendered to the End-User as "Error: <code>" rather than
    # redirected (oauth2_provider/authorize.html and logout_confirm.html).
    return {
        "comment": comment,
        "match": match,
        "tasks": [
            {
                "task": "Expect an error page",
                "match": match,
                "commands": [["wait", "xpath", "//*", 10, "Error:", "update-image-placeholder"]],
            }
        ],
    }


LOGOUT_BLOCK = {
    "match": LOGOUT,
    "tasks": [
        {
            "task": "Confirm logout",
            "optional": True,
            "match": LOGOUT,
            "commands": [["click", "css", "input[name='allow']"]],
        },
        {"task": "Verify Complete", "match": "*/test/*/post*"},
    ],
}


def overrides():
    result = {}
    for module in ("oidcc-prompt-login", "oidcc-max-age-1"):
        result[module] = {
            "browser": [
                authorize_block(
                    screenshot=True, comment="screenshots the re-login prompt during the second authorization"
                )
            ]
        }
    for module in (
        "oidcc-ensure-registered-redirect-uri",
        "oidcc-ensure-redirect-uri-in-authorization-request",
        "oidcc-redirect-uri-query-added",
        "oidcc-redirect-uri-query-mismatch",
    ):
        result[module] = {
            "browser": [error_page_block(AUTHORIZE, "expect an immediate error page instead of a redirect")]
        }
    for module in (
        "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
        "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
        "oidcc-rp-initiated-logout-modified-id-token-hint",
        "oidcc-rp-initiated-logout-bad-id-token-hint",
    ):
        result[module] = {
            "browser": [
                authorize_block(),
                error_page_block(LOGOUT, "expect an immediate error page instead of a redirect"),
            ]
        }
    return result


def config(alias, clients):
    return {
        "alias": alias,
        "description": f"django-oauth-toolkit tests/app/idp ({alias})",
        "server": {"discoveryUrl": f"{IDP}/o/.well-known/openid-configuration"},
        "client": clients[0],
        "client2": clients[1],
        "browser": [authorize_block(), LOGOUT_BLOCK],
        "override": overrides(),
    }


def main():
    files = {
        "dot-oidcc.json": config("dot", STATIC_CLIENTS),
        "dot-oidcc-dcr.json": config("dot-dcr", DCR_CLIENTS),
    }
    for name, content in files.items():
        with open(HERE / name, "w") as handle:
            json.dump(content, handle, indent=4)
            handle.write("\n")
        print(f"wrote {HERE / name}")


if __name__ == "__main__":
    main()
