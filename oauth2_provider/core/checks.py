from django.apps import apps
from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.db import router

from oauth2_provider.core.backends_oauthlib import JSONOAuthLibCore
from oauth2_provider.settings import oauth2_settings


# RFC 9700 (OAuth 2.0 Security Best Current Practice) behavior gates. Each tuple is
# (setting name, short description of the insecure behavior, check id). The default
# (``False``) keeps the insecure/legacy behavior and is scheduled to flip to ``True``
# in 4.0.
#
# Note: the OAUTH2_GRANT_TYPES_SUPPORTED / OAUTH2_RESPONSE_TYPES_SUPPORTED metadata
# lists are advertisement-only (RFC 8414 discovery) and do not gate what the endpoints
# accept, so they are deliberately not consulted here: while a behavior gate is False
# the server accepts the discouraged behavior regardless of what discovery advertises.
_BCP_GATES = [
    (
        "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT",
        "the OAuth 2.0 implicit grant is enabled (RFC 9700 §2.1.2)",
        "oauth2_provider.W001",
    ),
    (
        "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT",
        "the resource owner password credentials grant is enabled (RFC 9700 §2.4)",
        "oauth2_provider.W002",
    ),
    (
        "COMPLIANT_BCP_RFC9700_PKCE_METHOD",
        'the PKCE "plain" code_challenge_method is accepted (RFC 9700 §2.1.1)',
        "oauth2_provider.W003",
    ),
    (
        "COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT",
        "access tokens are accepted in the URI query string (RFC 9700 §4.3.2)",
        "oauth2_provider.W004",
    ),
    (
        "COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS",
        "the RFC 9207 `iss` authorization-response parameter is omitted (RFC 9700 §4.4)",
        "oauth2_provider.W005",
    ),
    (
        "COMPLIANT_BCP_RFC9700_TOKEN_STORAGE",
        "access and refresh tokens are stored in plaintext (RFC 9700 §4)",
        "oauth2_provider.W006",
    ),
]


def _pkce_not_required(settings):
    # A callable PKCE_REQUIRED is a per-client policy that cannot be evaluated
    # statically, so only a plain falsy value is flagged.
    return not callable(settings.PKCE_REQUIRED) and not settings.PKCE_REQUIRED


# Config-validation gates. These gates do not replace the settings they cover — the
# canonical settings stay the source of truth (and the registry of what to validate).
# Each tuple is (gate setting, predicate returning True when the covered setting is on
# an RFC 9700 non-compliant value, description, warning id, error id, fix hint).
# While the gate is False an insecure value produces a Warning; once the gate is True
# it produces an Error, so a non-compliant configuration cannot pass deploy checks.
_BCP_CONFIG_GATES = [
    (
        "COMPLIANT_BCP_RFC9700_REFRESH_TOKEN",
        lambda settings: not settings.REFRESH_TOKEN_REUSE_PROTECTION,
        "refresh token replay detection is disabled (§4.14.2)",
        "oauth2_provider.W007",
        "oauth2_provider.E002",
        (
            "Set OAUTH2_PROVIDER['REFRESH_TOKEN_REUSE_PROTECTION'] = True to revoke the "
            "whole token family when a refresh token is replayed."
        ),
    ),
    (
        "COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME",
        lambda settings: "http" in settings.ALLOWED_REDIRECT_URI_SCHEMES,
        "plaintext `http` redirect URIs are allowed (§2.1)",
        "oauth2_provider.W008",
        "oauth2_provider.E003",
        (
            "Remove 'http' from OAUTH2_PROVIDER['ALLOWED_REDIRECT_URI_SCHEMES'] to require "
            "https redirect URIs. Note this also disallows native-app loopback "
            "(http://127.0.0.1) callbacks per RFC 8252, so keep 'http' if you must support them."
        ),
    ),
    (
        "COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING",
        lambda settings: settings.ALLOW_URI_WILDCARDS,
        "wildcard redirect URIs are allowed instead of exact matching (§4.1.1)",
        "oauth2_provider.W009",
        "oauth2_provider.E004",
        "Set OAUTH2_PROVIDER['ALLOW_URI_WILDCARDS'] = False to require exact redirect URIs.",
    ),
    (
        "COMPLIANT_BCP_RFC9700_PKCE_REQUIRED",
        _pkce_not_required,
        "PKCE is not required (§2.1.1)",
        "oauth2_provider.W010",
        "oauth2_provider.E005",
        "Set OAUTH2_PROVIDER['PKCE_REQUIRED'] = True (or a per-client callable).",
    ),
]


@checks.register(checks.Tags.security, deploy=True)
def validate_bcp_configuration(app_configs, **kwargs):
    """
    Flag configuration that does not follow RFC 9700 (only under ``--deploy``).

    Behavior gates produce warnings while they still allow the legacy behavior (their
    runtime enforcement happens when the gate is True). Config-validation gates
    control the severity for the settings they cover: an insecure value is a Warning
    while the gate is False and an Error once it is True. All the gate defaults are
    scheduled to flip to the compliant value (True) in the 4.0 release.
    """
    messages = []
    for setting_name, behavior, check_id in _BCP_GATES:
        if not getattr(oauth2_settings, setting_name):
            messages.append(
                checks.Warning(
                    f"RFC 9700 (OAuth 2.0 Security BCP): {behavior}.",
                    hint=(
                        f"Set OAUTH2_PROVIDER['{setting_name}'] = True to adopt the "
                        "compliant behavior. This default is scheduled to change in 4.0."
                    ),
                    id=check_id,
                )
            )

    for gate_name, is_insecure, behavior, warning_id, error_id, fix_hint in _BCP_CONFIG_GATES:
        if not is_insecure(oauth2_settings):
            continue
        if not getattr(oauth2_settings, gate_name):
            messages.append(
                checks.Warning(
                    f"RFC 9700 (OAuth 2.0 Security BCP): {behavior}.",
                    hint=(
                        f"{fix_hint} This is a warning because OAUTH2_PROVIDER['{gate_name}'] "
                        "is False; the default is scheduled to change to True in 4.0, making "
                        "this configuration an error."
                    ),
                    id=warning_id,
                )
            )
        else:
            messages.append(
                checks.Error(
                    f"RFC 9700 (OAuth 2.0 Security BCP): {behavior}, and "
                    f"OAUTH2_PROVIDER['{gate_name}'] is True.",
                    hint=(
                        f"{fix_hint} Or set OAUTH2_PROVIDER['{gate_name}'] = False to downgrade "
                        "this to a warning."
                    ),
                    id=error_id,
                )
            )

    # Redacting tokens at rest is incompatible with the refresh-token grace period,
    # which must return the previously issued (plaintext) token from the database.
    if (
        oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE
        and oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS > 0
    ):
        messages.append(
            checks.Error(
                "Hashed token storage (COMPLIANT_BCP_RFC9700_TOKEN_STORAGE="
                "True) cannot be combined with a refresh-token grace period, which must "
                "return the previously issued token that is no longer stored in plaintext.",
                hint=(
                    "Set OAUTH2_PROVIDER['REFRESH_TOKEN_GRACE_PERIOD_SECONDS'] = 0, or keep "
                    "COMPLIANT_BCP_RFC9700_TOKEN_STORAGE = False."
                ),
                id="oauth2_provider.E001",
            )
        )

    return messages


@checks.register(checks.Tags.security)
def validate_request_body_configuration(app_configs, **kwargs):
    """
    Flag a request-body configuration that rejects every request it is set up to parse.

    ``REQUIRE_FORM_ENCODED_REQUEST_BODY`` makes the token, revocation, introspection,
    device-authorization and PAR endpoints answer 415 to any POST that is not
    ``application/x-www-form-urlencoded``, while the deprecated ``JSONOAuthLibCore``
    backend exists solely to read ``application/json`` bodies on those same endpoints.
    Combined, the gate rejects the request before the backend ever sees it, so *every*
    JSON request fails and the backend parses nothing -- always a misconfiguration
    rather than a deliberate posture.

    Unlike the RFC 9700 gates this is an internal-consistency check, so it is always on
    rather than ``--deploy``-only.
    """
    if not oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY:
        return []
    # OAUTH2_BACKEND_CLASS is an import-string setting, so this is the resolved class.
    if not issubclass(oauth2_settings.OAUTH2_BACKEND_CLASS, JSONOAuthLibCore):
        return []
    return [
        checks.Error(
            "OAUTH2_PROVIDER['REQUIRE_FORM_ENCODED_REQUEST_BODY'] is True while "
            "OAUTH2_PROVIDER['OAUTH2_BACKEND_CLASS'] reads application/json request "
            "bodies, so every request the backend is configured to parse is rejected "
            "with HTTP 415 before it reaches the backend.",
            hint=(
                "Remove the OAUTH2_BACKEND_CLASS override (the default "
                "'oauth2_provider.core.backends_oauthlib.OAuthLibCore' reads form-encoded "
                "bodies) and have clients send application/x-www-form-urlencoded request "
                "bodies, or set REQUIRE_FORM_ENCODED_REQUEST_BODY = False."
            ),
            id="oauth2_provider.E006",
        )
    ]


# Registered under the ``models`` tag rather than ``database``: this check only asks the
# configured routers where the token models would be written, which is static analysis and
# never opens a connection. Django 6.1 stopped running ``database``-tagged checks unless a
# database alias is passed explicitly (``manage.py check --database default``), because
# those checks may do more than static analysis -- keeping this one under that tag would
# silently disable it for everyone running a plain ``manage.py check``.
@checks.register(checks.Tags.models)
def validate_token_configuration(app_configs, **kwargs):
    databases = set(
        router.db_for_write(apps.get_model(model))
        for model in (
            oauth2_settings.ACCESS_TOKEN_MODEL,
            oauth2_settings.ID_TOKEN_MODEL,
            oauth2_settings.REFRESH_TOKEN_MODEL,
        )
    )

    # This is highly unlikely, but let's warn people just in case it does.
    # If the tokens were allowed to be in different databases this would require all
    # writes to have a transaction around each database. Instead, let's enforce that
    # they all live together in one database.
    # The tokens are not required to live in the default database provided the Django
    # routers know the correct database for them.
    if len(databases) > 1:
        return [checks.Error("The token models are expected to be stored in the same database.")]

    return []


@checks.register(checks.Tags.models)
def validate_swapped_model_consistency(app_configs, **kwargs):
    """
    Warn when the two circularly related token models are not swapped together.

    ``AccessToken.source_refresh_token`` points at ``REFRESH_TOKEN_MODEL`` and
    ``RefreshToken.access_token`` points back at ``ACCESS_TOKEN_MODEL``, so the two
    models reference each other. Swapping only one of them -- e.g. pointing
    ``OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL`` at a custom model while leaving
    ``RefreshToken`` on the default ``oauth2_provider.RefreshToken`` -- produces a
    circular foreign key that spans two apps. Django cannot order the initial
    migration for such a graph, which surfaces as ``fields.E304``/``E305`` reverse
    accessor clashes or "lazy reference ... isn't installed" migration errors.

    The two models must therefore live in the same app. This is only a warning:
    wiring the cross-app migration dependencies by hand is possible, but it is almost
    always a mistake rather than an intention.
    """
    access_app = oauth2_settings.ACCESS_TOKEN_MODEL.split(".", 1)[0]
    refresh_app = oauth2_settings.REFRESH_TOKEN_MODEL.split(".", 1)[0]
    if access_app != refresh_app:
        return [
            checks.Warning(
                "The configured AccessToken model "
                f"('{oauth2_settings.ACCESS_TOKEN_MODEL}') and RefreshToken model "
                f"('{oauth2_settings.REFRESH_TOKEN_MODEL}') are defined in different apps, "
                "but they reference each other with a circular foreign key.",
                hint=(
                    "Swap the AccessToken and RefreshToken models into the same app -- e.g. "
                    "point OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL and "
                    "OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL at models in one app. The IDToken "
                    "model is usually customized alongside them. See 'Extending the token "
                    "models' in the advanced topics documentation."
                ),
                id="oauth2_provider.W011",
            )
        ]

    return []


@checks.register(checks.Tags.models)
def validate_refresh_token_configuration(app_configs, **kwargs):
    """
    Warn when refresh token reuse protection is enabled without rotation.

    Reuse protection detects a replay by recognizing a refresh token that a *previous*
    rotation superseded. With ``ROTATE_REFRESH_TOKEN`` disabled nothing ever supersedes a
    refresh token -- the same value is handed back on every refresh -- so a replayed token
    is indistinguishable from a legitimate use and the family is never revoked. RFC 9700
    section 4.14.2 likewise defines replay detection in terms of rotation (or
    sender-constrained tokens), and ``docs/settings.rst`` already documents the pairing;
    this check enforces it.

    Unlike the RFC 9700 behavior gates in ``validate_bcp_configuration`` this is an
    internal-consistency check -- the combination does not do what it says on any setting
    of the compliance gates -- so it is always on rather than ``--deploy``-only.
    """
    if oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION and not oauth2_settings.ROTATE_REFRESH_TOKEN:
        return [
            checks.Warning(
                "OAUTH2_PROVIDER['REFRESH_TOKEN_REUSE_PROTECTION'] is enabled but "
                "OAUTH2_PROVIDER['ROTATE_REFRESH_TOKEN'] is disabled, so refresh token "
                "replay cannot be detected.",
                hint=(
                    "Set OAUTH2_PROVIDER['ROTATE_REFRESH_TOKEN'] = True so each refresh "
                    "supersedes the previous token and a replay of it is recognizable, or "
                    "set OAUTH2_PROVIDER['REFRESH_TOKEN_REUSE_PROTECTION'] = False to stop "
                    "claiming a protection that is not in effect. See RFC 9700 section "
                    "4.14.2."
                ),
                id="oauth2_provider.W012",
            )
        ]

    return []


@checks.register(checks.Tags.security)
def validate_access_token_expiry_configuration(app_configs, **kwargs):
    """
    Report a misconfigured ``ACCESS_TOKEN_EXPIRE_SECONDS`` at startup.

    Tagged ``security`` (not ``deploy``-only, unlike ``validate_bcp_configuration``) because
    the access token lifetime is the RFC 9700 §4 exposure window for a leaked token, and an
    untagged check is skipped entirely by tag-filtered runs such as ``manage.py check --tag
    security``.

    The setting may be a number of seconds, a ``timedelta``, or a callable taking the
    oauthlib request (see ``OAuth2ProviderSettings.access_token_expires_in``). A static
    value is resolved here so a bad one is reported by ``check`` rather than raising on
    the first token issued. A callable can only be type-checked -- its return value is
    validated per call, when there is a request to evaluate it against.
    """
    try:
        if callable(oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS):
            return []
        oauth2_settings.access_token_expires_in()
    # The setting is import-string aware, so a string that is not a dotted path to a
    # callable raises ImportError; report it here rather than crashing ``manage.py check``.
    except (ImproperlyConfigured, ImportError) as exc:
        return [
            checks.Error(
                str(exc),
                hint=(
                    "Set OAUTH2_PROVIDER['ACCESS_TOKEN_EXPIRE_SECONDS'] to a positive number "
                    "of seconds, a datetime.timedelta, or a callable taking the oauthlib "
                    "request and returning either."
                ),
                id="oauth2_provider.E006",
            )
        ]

    return []


@checks.register()
def validate_backchannel_logout(app_configs, **kwargs):
    errors = []

    if oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
        if not oauth2_settings.OIDC_ENABLED:
            errors.append(checks.Error("OIDC_ENABLED must be True to enable OIDC backchannel logout."))
        if not callable(oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER):
            errors.append(checks.Error("OIDC_BACKCHANNEL_LOGOUT_HANDLER must be a callable."))
        if not oauth2_settings.OIDC_ISS_ENDPOINT:
            errors.append(checks.Error("OIDC_ISS_ENDPOINT must be set to enable OIDC backchannel logout."))

    return errors
