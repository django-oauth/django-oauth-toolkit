"""Generate the suite configuration files in this directory.

The files differ only in the ``alias`` (the suite's per-configuration
namespace, which decides the callback URIs) and in the client block.
``dot-oidcc.json``, ``dot-oidcc-implicit.json`` and ``dot-oidcc-hybrid.json``
name the clients ``seed_idp.py`` creates for the authorization-code, implicit
and hybrid grant (an Application serves exactly one grant type, so each
``[client_registration=static_client]`` plan needs the matching pair);
``dot-oidcc-dcr.json`` only names the clients, for the
``[client_registration=dynamic_client]`` plans, where the suite registers them
itself through the RFC 7591 endpoint.

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
STATIC_CLIENTS = {
    "code": [
        {
            "client_id": "openid-conformance-suite-client-1",
            "client_secret": "openid-conformance-suite-secret-1",
        },
        {
            "client_id": "openid-conformance-suite-client-2",
            "client_secret": "openid-conformance-suite-secret-2",
        },
    ],
    "implicit": [
        {
            "client_id": "openid-conformance-suite-implicit-1",
            "client_secret": "openid-conformance-suite-implicit-secret-1",
        },
        {
            "client_id": "openid-conformance-suite-implicit-2",
            "client_secret": "openid-conformance-suite-implicit-secret-2",
        },
    ],
    "hybrid": [
        {
            "client_id": "openid-conformance-suite-hybrid-1",
            "client_secret": "openid-conformance-suite-hybrid-secret-1",
        },
        {
            "client_id": "openid-conformance-suite-hybrid-2",
            "client_secret": "openid-conformance-suite-hybrid-secret-2",
        },
    ],
}
DCR_CLIENTS = [
    {"client_name": "openid-conformance-suite-client-1"},
    {"client_name": "openid-conformance-suite-client-2"},
]


def login_task(screenshot=None):
    commands = []
    if screenshot:
        # Fills the module's screenshot placeholder with the login page, which is
        # how the prompt=login / max_age modules prove the End-User was re-prompted.
        # "update-image-placeholder-optional" leaves the module WAITING for a manual
        # upload when the prompt never appears; the non-optional form fails it
        # after the timeout instead, which is the right outcome for an OP gap.
        commands.append(["wait", "xpath", "//*", 10, "Log In", screenshot])
    commands += [
        ["text", "id", "id_username", USERNAME],
        ["text", "id", "id_password", PASSWORD],
        ["click", "css", "button[type='submit']"],
    ]
    return {"task": "Login", "optional": True, "match": LOGIN, "commands": commands}


# "optional" on the click: a module that lands on an error page at the same URL
# must not fail on the missing button (the suite reports what happened instead).
CONSENT = {
    "task": "Consent",
    "optional": True,
    "match": AUTHORIZE,
    "commands": [["click", "css", "input[name='allow']", "optional"]],
}
VERIFY_CALLBACK = {
    "task": "Verify Complete",
    "match": "*/test/*/callback*",
    "commands": [["wait", "id", "submission_complete", 10]],
}


def authorize_block(screenshot=None, comment=None):
    block = {"match": AUTHORIZE, "tasks": [login_task(screenshot), CONSENT, VERIFY_CALLBACK]}
    if comment:
        block = {"comment": comment, **block}
    return block


def error_page_block(match, comment, login_first=False):
    # Fatal errors are rendered to the End-User as "Error: <code>" rather than
    # redirected (oauth2_provider/authorize.html and logout_confirm.html). The
    # authorization endpoint authenticates the End-User before it validates the
    # request, so a module that starts with a fresh browser session sees the
    # login page first and the error page only after logging in.
    tasks = [login_task()] if login_first else []
    tasks.append(
        {
            "task": "Expect an error page",
            "match": match,
            "commands": [["wait", "xpath", "//*", 10, "Error:", "update-image-placeholder"]],
        }
    )
    return {"comment": comment, "match": match, "tasks": tasks}


CONFIRM_LOGOUT = {
    "task": "Confirm logout",
    "optional": True,
    "match": LOGOUT,
    "commands": [["click", "css", "input[name='allow']", "optional"]],
}
LOGOUT_BLOCK = {
    "match": LOGOUT,
    "tasks": [CONFIRM_LOGOUT, {"task": "Verify Complete", "match": "*/test/*/post*"}],
}
# Without a post_logout_redirect_uri the toolkit sends the End-User to the site
# root after logging them out; these modules want a screenshot of that page.
LOGOUT_TO_HOME_BLOCK = {
    "comment": "no post_logout_redirect_uri: expect the IdP home page after logout",
    "match": LOGOUT,
    "tasks": [
        CONFIRM_LOGOUT,
        {
            "task": "Expect the IdP home page",
            "match": f"{IDP}/",
            "commands": [
                ["wait", "xpath", "//*", 10, "Welcome to the Identity Provider", "update-image-placeholder"]
            ],
        },
    ],
}


def overrides():
    result = {}
    result["oidcc-prompt-login"] = {
        "browser": [
            authorize_block(
                screenshot="update-image-placeholder-optional",
                comment="screenshots the re-login prompt during the second authorization",
            )
        ]
    }
    result["oidcc-max-age-1"] = {
        "browser": [
            authorize_block(
                screenshot="update-image-placeholder",
                comment="screenshots the re-login prompt the elapsed max_age must trigger",
            )
        ]
    }
    # These modules redirect to the authorization endpoint only to look at the
    # login page (it should show the registered logo / policy / terms link) and
    # end once the screenshot placeholder is filled; without it they sit WAITING.
    for module, expectation in (
        ("oidcc-registration-logo-uri", "logo"),
        ("oidcc-registration-policy-uri", "policy document link"),
        ("oidcc-registration-tos-uri", "terms of service link"),
    ):
        result[module] = {
            "browser": [
                authorize_block(
                    screenshot="update-image-placeholder",
                    comment=f"screenshots the login page, which should show the client's {expectation}",
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
            "browser": [
                error_page_block(AUTHORIZE, "expect an error page instead of a redirect", login_first=True)
            ]
        }
    for module in (
        "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri",
        "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri",
        "oidcc-rp-initiated-logout-modified-id-token-hint",
        "oidcc-rp-initiated-logout-bad-id-token-hint",
        # The toolkit refuses a post_logout_redirect_uri that comes without an
        # id_token_hint (RP-Initiated Logout 1.0 section 2 lets the OP decline).
        "oidcc-rp-initiated-logout-no-id-token-hint",
    ):
        result[module] = {
            "browser": [
                authorize_block(),
                error_page_block(LOGOUT, "expect an immediate error page instead of a redirect"),
            ]
        }
    for module in (
        "oidcc-rp-initiated-logout-no-params",
        "oidcc-rp-initiated-logout-no-post-logout-redirect-uri",
        "oidcc-rp-initiated-logout-only-state",
    ):
        result[module] = {"browser": [authorize_block(), LOGOUT_TO_HOME_BLOCK]}
    return result


def config(alias, clients, static=True):
    result = {
        "alias": alias,
        "description": f"django-oauth-toolkit tests/app/idp ({alias})",
        "server": {"discoveryUrl": f"{IDP}/o/.well-known/openid-configuration"},
        "client": clients[0],
        "client2": clients[1],
        "browser": [authorize_block(), LOGOUT_BLOCK],
        "override": overrides(),
    }
    if static:
        # The oidcc-server-client-secret-post module takes its client from this
        # block; the second seeded client serves, the module runs on its own.
        result["client_secret_post"] = clients[1]
    return result


def main():
    files = {
        "dot-oidcc.json": config("dot", STATIC_CLIENTS["code"]),
        "dot-oidcc-implicit.json": config("dot-implicit", STATIC_CLIENTS["implicit"]),
        "dot-oidcc-hybrid.json": config("dot-hybrid", STATIC_CLIENTS["hybrid"]),
        "dot-oidcc-dcr.json": config("dot-dcr", DCR_CLIENTS, static=False),
    }
    for name, content in files.items():
        with open(HERE / name, "w") as handle:
            json.dump(content, handle, indent=4)
            handle.write("\n")
        print(f"wrote {HERE / name}")


if __name__ == "__main__":
    main()
