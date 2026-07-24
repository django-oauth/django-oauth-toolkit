from django.apps import apps
from django.core import checks
from django.db import router

from .settings import oauth2_settings


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


@checks.register(checks.Tags.database)
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


@checks.register(checks.Tags.security)
def validate_jwt_bearer_grant_configuration(app_configs, **kwargs):
    """
    Warn when the RFC 7523 JWT bearer grant is enabled but no way to trust an
    assertion issuer is configured, which makes the grant unusable: every request
    would be rejected because no issuer's keys can be resolved.
    """
    messages = []
    if not oauth2_settings.JWT_BEARER_GRANT_ENABLED:
        return messages

    has_trusted_issuers = bool(oauth2_settings.JWT_BEARER_TRUSTED_ISSUERS)
    has_application_keys = False
    application_model = apps.get_model(oauth2_settings.APPLICATION_MODEL)
    db = router.db_for_read(application_model)
    try:
        has_application_keys = (
            application_model._default_manager.using(db)
            .filter(authorization_grant_type=application_model.GRANT_JWT_BEARER)
            .exclude(client_jwks="", client_jwks_uri="")
            .exists()
        )
    except Exception:  # noqa: BLE001 - the database may be unavailable at check time
        # Can't inspect applications (e.g. before migrate); fall back to the
        # settings-only signal so the check never crashes system startup.
        has_application_keys = False

    if not has_trusted_issuers and not has_application_keys:
        messages.append(
            checks.Warning(
                "JWT_BEARER_GRANT_ENABLED is True but no assertion issuer can be trusted: "
                "no application registered for the jwt-bearer grant has client_jwks / "
                "client_jwks_uri set, and JWT_BEARER_TRUSTED_ISSUERS is empty.",
                hint=(
                    "Configure client_jwks (or client_jwks_uri) on the applications that use "
                    "the grant, or add entries to OAUTH2_PROVIDER['JWT_BEARER_TRUSTED_ISSUERS']."
                ),
                id="oauth2_provider.W011",
            )
        )
    return messages
