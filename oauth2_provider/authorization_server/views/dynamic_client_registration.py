"""
Views implementing OAuth 2.0 Dynamic Client Registration Protocol.

RFC 7591 — POST /register/
RFC 7592 — GET/PUT/DELETE /register/{client_id}/
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Any

from django.contrib.auth.base_user import AbstractBaseUser
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from oauth2_provider.authorization_server.oidc.client_metadata import (
    UnsupportedClientMetadataError,
    backchannel_logout_session_required,
    backchannel_logout_uri,
    id_token_signed_response_alg,
    id_token_signing_algorithm,
    request_object_signing_alg,
    request_uris,
    userinfo_signed_response_alg,
    userinfo_signing_algorithm,
)
from oauth2_provider.authorization_server.oidc.request_objects import request_objects_enabled
from oauth2_provider.authorization_server.views.metadata import bcp_filter_response_types
from oauth2_provider.core.compat import login_not_required
from oauth2_provider.core.utils import jwk_allows_verification, parse_bearer_token
from oauth2_provider.models import (
    AbstractAccessToken,
    AbstractApplication,
    get_access_token_model,
    get_application_model,
    set_token_value,
)
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger(__name__)

# RFC 7591 grant type name → DOT AbstractApplication constant
GRANT_TYPE_MAP = {
    "authorization_code": "authorization-code",
    "implicit": "implicit",
    "password": "password",
    "client_credentials": "client-credentials",
    "urn:ietf:params:oauth:grant-type:device_code": "urn:ietf:params:oauth:grant-type:device_code",
}

# Grant types that are handled automatically by DOT alongside authorization_code
IGNORED_GRANT_TYPES = {"refresh_token"}

# The one combination of grant types DOT serves with a single application: an
# OpenID Connect hybrid client, whose response types need both (OpenID Connect
# Dynamic Client Registration 1.0 section 2).
HYBRID_GRANT_TYPES = frozenset({"authorization_code", "implicit"})

# DOT grant types for which Application.clean() requires redirect_uris
REDIRECT_REQUIRED_GRANT_TYPES = {
    AbstractApplication.GRANT_AUTHORIZATION_CODE,
    AbstractApplication.GRANT_IMPLICIT,
    AbstractApplication.GRANT_OPENID_HYBRID,
}

# The response types an application of each DOT grant type can use, in the
# canonical form registration responses report them in. They mirror
# OAuth2Validator.validate_response_type; _served_response_types narrows them
# to the ones this server serves. A grant type absent here serves no response
# type.
RESPONSE_TYPES_BY_GRANT = {
    AbstractApplication.GRANT_AUTHORIZATION_CODE: ("code",),
    AbstractApplication.GRANT_IMPLICIT: ("id_token", "id_token token", "token"),
    AbstractApplication.GRANT_OPENID_HYBRID: ("code id_token", "code token", "code id_token token"),
}

# RFC 7591 section 2 metadata shown to the End-User during approval. Each is
# stored on the Application field of the same name.
DISPLAY_URI_FIELDS = ("client_uri", "logo_uri", "policy_uri", "tos_uri")
# Matches the max_length of those Application fields.
DISPLAY_URI_MAX_LENGTH = 500
_https_url_validator = URLValidator(schemes=["https"])


def _response_type_values(response_type: str) -> frozenset[str] | None:
    """The values of a space-delimited response type, whose order is not
    significant (RFC 6749 section 3.1.1), or None when a value repeats: the
    authorization endpoint can never serve such a response type."""
    values = response_type.split()
    unique = frozenset(values)
    return unique if len(unique) == len(values) else None


def _served_response_types(dot_grant: str) -> list[str]:
    """The response types an application of *dot_grant* can use on this server.

    That is the grant's own response types, less any the server does not
    advertise: the discovery documents' list (OIDC_RESPONSE_TYPES_SUPPORTED with
    OpenID Connect enabled, OAUTH2_RESPONSE_TYPES_SUPPORTED otherwise), less
    the implicit ones COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT makes the
    authorization endpoint refuse. Without OpenID Connect, for instance, no
    response type with ``id_token`` is served.
    """
    if oauth2_settings.OIDC_ENABLED:
        supported = oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED
    else:
        supported = oauth2_settings.OAUTH2_RESPONSE_TYPES_SUPPORTED
    # A non-string entry can never be served; drop it before the BCP filter,
    # which splits each entry.
    advertised = {
        _response_type_values(rt)
        for rt in bcp_filter_response_types([rt for rt in supported if isinstance(rt, str)])
    }
    return [
        rt for rt in RESPONSE_TYPES_BY_GRANT.get(dot_grant, ()) if _response_type_values(rt) in advertised
    ]


def _error_response(error, description, status=400):
    response = JsonResponse({"error": error, "error_description": description}, status=status)
    if status == 401:
        # RFC 6750 §3: 401 responses to requests to a Bearer-protected
        # resource must carry a WWW-Authenticate: Bearer challenge.
        if error == "invalid_token":
            response["WWW-Authenticate"] = 'Bearer error="invalid_token", error_description="{}"'.format(
                description
            )
        else:
            # No Bearer credentials were attempted; RFC 6750 §3.1 says the
            # challenge should not include an error code in that case.
            response["WWW-Authenticate"] = "Bearer"
    return response


def _check_permissions(request):
    """
    Run all DCR_REGISTRATION_PERMISSION_CLASSES; return True if all pass.

    Fails closed: an empty DCR_REGISTRATION_PERMISSION_CLASSES denies all
    registration. Open registration must be requested explicitly by
    configuring AllowAllDCRPermission.
    """
    permission_classes = oauth2_settings.DCR_REGISTRATION_PERMISSION_CLASSES
    if not permission_classes:
        return False
    for cls in permission_classes:
        instance = cls()
        if not instance.has_permission(request):
            return False
    return True


def _validation_error_description(exc):
    """
    Build an RFC 7591 error_description from a Django ValidationError.

    Uses only the validation messages, never the exception's repr, so no
    internal details can leak into the API response.
    """
    if hasattr(exc, "message_dict"):
        return "; ".join(
            "{}: {}".format(field, " ".join(messages)) for field, messages in exc.message_dict.items()
        )
    return "; ".join(exc.messages)


def _parse_metadata(body):
    """
    Parse JSON body and return (data_dict, error_response).

    Returns (None, JsonResponse) on parse failure, (dict, None) on success.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None, _error_response("invalid_client_metadata", "Request body must be valid JSON")
    if not isinstance(data, dict):
        return None, _error_response("invalid_client_metadata", "Request body must be a JSON object")
    return data, None


def _display_uri(data: dict[str, Any], name: str) -> tuple[str, JsonResponse | None]:
    """
    Read the display URI *name* from RFC 7591 metadata *data*.

    Returns (value, error_response). An absent, null or empty value yields ""
    so a request is a full replacement of the metadata (RFC 7592 section 2.2). The
    value is shown to the End-User as a link or image, so only an absolute
    https URL is accepted; checking here reports the RFC 7591 field name.
    """
    value = data.get(name)
    if value is None or value == "":
        return "", None
    if not isinstance(value, str):
        return "", _error_response("invalid_client_metadata", f"{name} must be a string")
    if len(value) > DISPLAY_URI_MAX_LENGTH:
        return "", _error_response(
            "invalid_client_metadata", f"{name} must be at most {DISPLAY_URI_MAX_LENGTH} characters"
        )
    try:
        _https_url_validator(value)
    except ValidationError:
        return "", _error_response("invalid_client_metadata", f"{name} must be an absolute https URL")
    return value, None


def _resolve_grant_type(grant_types: list[str]) -> tuple[str | None, JsonResponse | None]:
    """
    Resolve RFC 7591 grant_types list to a single DOT grant type constant.

    ``authorization_code`` together with ``implicit`` resolves to the OpenID
    Connect hybrid grant, which serves both.

    Returns (dot_grant_type, error_response).
    """
    if not grant_types:
        return None, _error_response("invalid_client_metadata", "grant_types must not be empty")

    meaningful = [g for g in grant_types if g not in IGNORED_GRANT_TYPES]

    if not meaningful:
        # Only refresh_token (or empty after filtering) is invalid
        return None, _error_response(
            "invalid_client_metadata",
            "grant_types must contain at least one grant type other than refresh_token",
        )

    if set(meaningful) == HYBRID_GRANT_TYPES:
        if not _served_response_types(AbstractApplication.GRANT_OPENID_HYBRID):
            # Without OpenID Connect (or with its hybrid response types not
            # offered) the client could use none of the response types it
            # registers both grants for (RFC 7591 section 2.1).
            return None, _error_response(
                "invalid_client_metadata",
                "grant_types authorization_code with implicit registers an OpenID Connect hybrid "
                "client, and this server serves none of the hybrid response types",
            )
        return AbstractApplication.GRANT_OPENID_HYBRID, None

    if len(meaningful) > 1:
        return None, _error_response(
            "invalid_client_metadata",
            "DOT only supports one grant type per application; "
            "multiple non-refresh_token grant types are not supported, "
            "except authorization_code with implicit for an OpenID Connect hybrid client",
        )

    grant_type = meaningful[0]
    dot_grant = GRANT_TYPE_MAP.get(grant_type)
    if dot_grant is None:
        return None, _error_response(
            "invalid_client_metadata",
            f"Unsupported grant_type: {grant_type!r}",
        )
    return dot_grant, None


def _check_response_types(data: dict[str, Any], dot_grant: str) -> JsonResponse | None:
    """
    Check the requested response_types against the resolved DOT grant type.

    RFC 7591 section 2.1 asks the server to keep a client from registering
    itself into an inconsistent state, so every response type must be one the
    application will be able to use (see _served_response_types): OpenID
    Connect Dynamic Client Registration 1.0 section 2 lists the grant types
    each response type needs, DOT serves one grant type per application, so a
    hybrid client cannot use the plain ``code`` response type either, and the
    server's own configuration can rule response types out.

    response_types is not stored. Whether or not the client sent it, the
    server provisions every response type the grant serves and the response
    reports them (RFC 7591 sections 2 and 3.2.1), so an omitted field, whose
    default of ``code`` a hybrid client cannot use, has nothing to check.

    Returns an error response, or None when the response types are consistent.
    """
    response_types = data.get("response_types")
    if response_types is None:
        return None
    if not isinstance(response_types, list):
        return _error_response("invalid_client_metadata", "response_types must be an array")
    if not all(isinstance(rt, str) for rt in response_types):
        return _error_response("invalid_client_metadata", "Each response_type must be a string")

    served = {_response_type_values(rt) for rt in _served_response_types(dot_grant)}
    grant_serves = {_response_type_values(rt) for rt in RESPONSE_TYPES_BY_GRANT.get(dot_grant, ())}
    for response_type in response_types:
        values = _response_type_values(response_type)
        if values in served:
            continue
        if values is None:
            reason = "repeats a value"
        elif values in grant_serves:
            # Consistent with the grant, but the server's configuration rules
            # it out (no OpenID Connect, or the RFC 9700 implicit gate).
            reason = "is not supported by this server"
        else:
            grant_types = ", ".join(_dot_grant_to_rfc_grant_types(dot_grant))
            reason = f"is inconsistent with grant_types [{grant_types}]"
        return _error_response("invalid_client_metadata", f"response_type {response_type!r} {reason}")
    return None


def _build_application_kwargs(
    data: dict[str, Any],
    *,
    client_secret: str = "",
    client_secret_is_hashed: bool = False,
    current_algorithm: str = "",
) -> tuple[dict[str, Any] | None, JsonResponse | None]:
    """
    Convert RFC 7591 metadata dict to Application field kwargs.

    On an update (RFC 7592 PUT) the caller passes the stored ``client_secret``,
    whether the application reports it as hashed, and the stored
    ``algorithm``, so a switch to client_secret_jwt can be refused for a
    hashed secret and a client echoing the value a previous response reported
    is not refused. Registration leaves them at their defaults: a freshly
    issued secret is never hashed and there is no algorithm to echo. Returns
    (kwargs_dict, error_response).
    """
    kwargs = {}

    # redirect_uris
    redirect_uris = data.get("redirect_uris", [])
    if not isinstance(redirect_uris, list):
        return None, _error_response("invalid_client_metadata", "redirect_uris must be an array")
    if not all(isinstance(uri, str) for uri in redirect_uris):
        return None, _error_response("invalid_client_metadata", "Each redirect_uri must be a string")
    kwargs["redirect_uris"] = " ".join(redirect_uris)

    # post_logout_redirect_uris (OpenID Connect RP-Initiated Logout 1.0 section
    # 3.1). Always set, so a PUT that omits it clears it (full replacement,
    # RFC 7592 section 2.2). Application.clean() validates each entry like a
    # redirect_uri, and in strict mode refuses http for a public client.
    post_logout_redirect_uris = data.get("post_logout_redirect_uris", [])
    if not isinstance(post_logout_redirect_uris, list):
        return None, _error_response("invalid_client_metadata", "post_logout_redirect_uris must be an array")
    if not all(isinstance(uri, str) for uri in post_logout_redirect_uris):
        return None, _error_response(
            "invalid_client_metadata", "Each post_logout_redirect_uri must be a string"
        )
    # The list is stored space-joined and read back split, so an empty entry or
    # one containing whitespace would not come back as the client sent it.
    if any(uri.split() != [uri] for uri in post_logout_redirect_uris):
        return None, _error_response(
            "invalid_client_metadata",
            "Each post_logout_redirect_uri must be a non-empty URI without whitespace",
        )
    kwargs["post_logout_redirect_uris"] = " ".join(post_logout_redirect_uris)

    # client_name — always set so a request is a full replacement of the
    # metadata (RFC 7592 §2.2): on PUT an omitted client_name resets
    # Application.name to empty, consistent with the other fields below. On
    # POST this is equivalent to the model's blank default.
    kwargs["name"] = data.get("client_name", "")

    # client_uri, logo_uri, policy_uri, tos_uri — likewise always set.
    for name in DISPLAY_URI_FIELDS:
        value, err = _display_uri(data, name)
        if err:
            return None, err
        kwargs[name] = value

    # grant_types → authorization_grant_type
    grant_types = data.get("grant_types", ["authorization_code"])
    if not isinstance(grant_types, list):
        return None, _error_response("invalid_client_metadata", "grant_types must be an array")
    if not all(isinstance(g, str) for g in grant_types):
        return None, _error_response("invalid_client_metadata", "Each grant_type must be a string")

    dot_grant, err = _resolve_grant_type(grant_types)
    if err:
        return None, err
    kwargs["authorization_grant_type"] = dot_grant

    err = _check_response_types(data, dot_grant)
    if err:
        return None, err

    # Fail early with RFC 7591 field names/values; deferring to
    # Application.clean() would surface DOT's internal grant type constants
    # (e.g. "authorization-code") in the error_description.
    if dot_grant in REDIRECT_REQUIRED_GRANT_TYPES and not redirect_uris:
        rfc_grant = _dot_grant_to_rfc_grant_types(dot_grant)[0]
        return None, _error_response(
            "invalid_client_metadata",
            f"redirect_uris is required for grant type {rfc_grant!r}",
        )

    # backchannel_logout_uri — read through the shared OIDC client metadata module so the
    # dcr and cimd paths provision it identically. None means the parameter was not read
    # (back-channel logout is off); otherwise it is always set, so a PUT omitting it
    # clears the value (RFC 7592 section 2.2), like client_name above.
    try:
        logout_uri = backchannel_logout_uri(data)
    except UnsupportedClientMetadataError as exc:
        return None, _error_response("invalid_client_metadata", str(exc))
    if logout_uri is not None:
        kwargs["backchannel_logout_uri"] = logout_uri

    # backchannel_logout_session_required — this server issues no sid, so true cannot be
    # honoured. A registration can be told so: the client is registered anyway and the
    # response reports false (RFC 7591 section 3.2.1), so a client that cannot work
    # without sid can see that and decide what to do. Only the type is checked here.
    try:
        backchannel_logout_session_required(data)
    except UnsupportedClientMetadataError as exc:
        return None, _error_response("invalid_client_metadata", str(exc))

    # token_endpoint_auth_method → client_type (+ token_endpoint_auth_method field)
    SUPPORTED_AUTH_METHODS = (
        "none",
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
    )
    auth_method = data.get("token_endpoint_auth_method", "client_secret_basic")
    if auth_method not in SUPPORTED_AUTH_METHODS:
        return None, _error_response(
            "invalid_client_metadata",
            f"Unsupported token_endpoint_auth_method: {auth_method!r}. "
            f"Supported values: {', '.join(SUPPORTED_AUTH_METHODS)}",
        )
    kwargs["token_endpoint_auth_method"] = auth_method
    if auth_method == "none":
        kwargs["client_type"] = "public"
    else:
        kwargs["client_type"] = "confidential"

    # jwks / jwks_uri (RFC 7591 section 2: mutually exclusive). Always set both
    # kwargs so a PUT without them resets the fields (full-replacement
    # semantics, RFC 7592 section 2.2), like client_name above.
    jwks = data.get("jwks")
    jwks_uri = data.get("jwks_uri")
    if jwks_uri is not None and not isinstance(jwks_uri, str):
        return None, _error_response("invalid_client_metadata", "jwks_uri must be a string")
    if jwks_uri is not None:
        # An empty or whitespace-only jwks_uri counts as absent, so the
        # RFC-named checks below apply instead of Application.clean()'s
        # model-field wording surfacing later.
        jwks_uri = jwks_uri.strip() or None
    if jwks is not None and jwks_uri is not None:
        return None, _error_response("invalid_client_metadata", "jwks and jwks_uri are mutually exclusive")
    if jwks is not None and (not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list)):
        return None, _error_response(
            "invalid_client_metadata", 'jwks must be a JWK Set object with a "keys" array'
        )
    if jwks is not None:
        # Validate the key material here too, so every failure speaks RFC 7591
        # ("jwks") instead of Application.clean()'s internal field wording.
        keys = jwks["keys"]
        if not keys:
            return None, _error_response("invalid_client_metadata", "jwks must contain at least one key")
        if not all(isinstance(key, dict) for key in keys):
            return None, _error_response("invalid_client_metadata", "each key in jwks must be a JSON object")
        if any(isinstance(key, dict) and _PRIVATE_JWK_MEMBERS.intersection(key) for key in keys):
            return None, _error_response(
                "invalid_client_metadata", "jwks must contain public keys only, never private keys"
            )
        if not any(isinstance(key, dict) and jwk_allows_verification(key) for key in keys):
            return None, _error_response(
                "invalid_client_metadata",
                "jwks must contain at least one key usable for signature verification",
            )
    # Validate here with the RFC 7591 field name; deferring to
    # Application.clean() would surface the internal client_jwks_uri field
    # name in the error_description.
    if jwks_uri is not None and not jwks_uri.lower().startswith("https://"):
        return None, _error_response("invalid_client_metadata", "jwks_uri must use the https scheme")
    kwargs["client_jwks"] = json.dumps(jwks) if jwks is not None else ""
    kwargs["client_jwks_uri"] = jwks_uri or ""

    # Fail early with the RFC 7591 field names; Application.clean() re-checks
    # with model-level wording.
    if auth_method == "private_key_jwt" and jwks is None and jwks_uri is None:
        return None, _error_response("invalid_client_metadata", "private_key_jwt requires jwks or jwks_uri")
    # For client_secret_jwt the secret is the HMAC key, so it must be stored in
    # plaintext (the raw secret is returned in the registration response either
    # way); every other method keeps the hashed-at-rest default.
    kwargs["hash_client_secret"] = auth_method != "client_secret_jwt"
    # A PUT switching a client registered with another method to
    # client_secret_jwt finds its secret already hashed, and a hash cannot be
    # turned back into the key. Application.clean() refuses that too, but in
    # terms of hash_client_secret and client_secret; fail here with the RFC names.
    # The caller asks the application itself, as Application.clean() does, so a
    # swapped model's own detection applies.
    if auth_method == "client_secret_jwt" and client_secret_is_hashed:
        return None, _error_response(
            "invalid_client_metadata",
            "token_endpoint_auth_method 'client_secret_jwt' requires a plaintext client secret, "
            "but this client's secret is stored hashed and cannot be recovered; register a new "
            "client to use client_secret_jwt",
        )

    # id_token_signed_response_alg → algorithm (OpenID Connect Dynamic Client
    # Registration 1.0 section 2). Always set, so a PUT without it resets to
    # the default like the fields above (RFC 7592 section 2.2).
    #
    # HS256 is never granted on request. The client facts derived above decide
    # whether an echoed administrator-set value is kept on a PUT: the client
    # must stay on client_secret_jwt and off the implicit/hybrid grants, and
    # for HS256, which signs with the plaintext secret, the secret must be long
    # enough to be the key. Application.clean() enforces the HS256 rule (bar
    # the length), but in terms of hash_client_secret and algorithm, fields a
    # registering client cannot set; the helper fails with the RFC names
    # instead.
    try:
        kwargs["algorithm"] = id_token_signing_algorithm(
            data,
            current=current_algorithm,
            client_type=kwargs["client_type"],
            token_endpoint_auth_method=auth_method,
            authorization_grant_type=dot_grant,
            client_secret=client_secret,
        )
    except UnsupportedClientMetadataError as exc:
        return None, _error_response("invalid_client_metadata", str(exc))

    # userinfo_signed_response_alg (OpenID Connect Dynamic Client Registration
    # 1.0 section 2). Always set, so a PUT without it returns UserInfo as plain
    # JSON again (RFC 7592 section 2.2).
    try:
        kwargs["userinfo_signed_response_alg"] = userinfo_signing_algorithm(data)
    except UnsupportedClientMetadataError as exc:
        return None, _error_response("invalid_client_metadata", str(exc))

    # request_uris / request_object_signing_alg (OpenID Connect Dynamic Client
    # Registration 1.0 section 2), set so a PUT without them resets them. While
    # request objects are disabled they are ignored and stored values are left
    # as they are, so a client echoing them back on a PUT loses nothing.
    if request_objects_enabled():
        try:
            kwargs["request_uris"] = request_uris(data)
            kwargs["request_object_signing_alg"] = request_object_signing_alg(
                data, has_keys=bool(kwargs["client_jwks"] or kwargs["client_jwks_uri"])
            )
        except UnsupportedClientMetadataError as exc:
            return None, _error_response("invalid_client_metadata", str(exc))

    return kwargs, None


def _issue_registration_token(application: AbstractApplication, user: AbstractBaseUser | None) -> str:
    """
    Create a new registration AccessToken for *application* and return its raw value.

    Only the raw value is returned, because reading it back off the row is not an
    option: under ``COMPLIANT_BCP_RFC9700_TOKEN_STORAGE`` the ``token`` column is left
    blank and only the lookup checksum is persisted.

    Token scope is ``oauth2_settings.DCR_REGISTRATION_SCOPE``.
    Expiry: far-future (year 9999) when ``DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS`` is None,
    otherwise ``now + DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS`` seconds.
    """
    from oauth2_provider.generators import generate_client_secret  # reuse secret-quality token generator

    AccessToken = get_access_token_model()

    expire_seconds = oauth2_settings.DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS
    if expire_seconds is None:
        expires = datetime(9999, 12, 31, 23, 59, 59, tzinfo=dt_timezone.utc)
    else:
        expires = timezone.now() + timedelta(seconds=expire_seconds)

    raw_token = generate_client_secret()
    token = AccessToken(
        application=application,
        user=user,
        expires=expires,
        scope=oauth2_settings.DCR_REGISTRATION_SCOPE,
    )
    # Assigning ``token`` directly would store a reusable credential in cleartext even
    # when the deployment asked for hashed-at-rest storage.
    set_token_value(token, raw_token)
    token.save()
    return raw_token


def _application_to_response(
    application: AbstractApplication, registration_access_token: str, request: HttpRequest
) -> dict[str, Any]:
    """Build the RFC 7591 response dict for *application*.

    *registration_access_token* is the raw token value rather than the model instance:
    under hashed-at-rest storage the stored column is blank, so the value can only come
    from whoever just issued it or from the request that presented it.
    """
    # Registrations persist the method explicitly; legacy rows (blank field)
    # keep the old client_type-based inference.
    auth_method = application.token_endpoint_auth_method or (
        "none" if application.client_type == "public" else "client_secret_basic"
    )
    data = {
        "client_id": application.client_id,
        # RFC 7591 section 3.2.1: seconds since the epoch at which the client_id
        # was issued. It never changes, so management responses repeat it.
        "client_id_issued_at": int(application.created.timestamp()),
        "redirect_uris": application.redirect_uris.split() if application.redirect_uris else [],
        "post_logout_redirect_uris": (
            application.post_logout_redirect_uris.split() if application.post_logout_redirect_uris else []
        ),
        "grant_types": _dot_grant_to_rfc_grant_types(application.authorization_grant_type),
        # Derived from the grant, see _check_response_types. Always present: an
        # omitted response_types means "code" (RFC 7591 section 2).
        "response_types": _served_response_types(application.authorization_grant_type),
        "token_endpoint_auth_method": auth_method,
        "registration_access_token": registration_access_token,
        "registration_client_uri": request.build_absolute_uri(
            reverse("oauth2_provider:dcr-register-management", kwargs={"client_id": application.client_id})
        ),
    }
    if application.name:
        data["client_name"] = application.name
    for name in DISPLAY_URI_FIELDS:
        value = getattr(application, name)
        if value:
            data[name] = value
    if application.client_jwks:
        jwks = _stored_jwks_for_response(application)
        if jwks is not None:
            data["jwks"] = jwks
    if application.client_jwks_uri:
        data["jwks_uri"] = application.client_jwks_uri
    # Reported even when the server chose it (OpenID Connect Dynamic Client
    # Registration 1.0 section 3.2: the response includes every registered
    # value, including those the provider provisioned itself).
    signing_alg = id_token_signed_response_alg(application)
    if signing_alg is not None:
        data["id_token_signed_response_alg"] = signing_alg
    userinfo_alg = userinfo_signed_response_alg(application)
    if userinfo_alg is not None:
        data["userinfo_signed_response_alg"] = userinfo_alg
    if application.request_uris:
        data["request_uris"] = application.request_uris.split()
    if application.request_object_signing_alg:
        data["request_object_signing_alg"] = application.request_object_signing_alg
    if application.backchannel_logout_uri:
        data["backchannel_logout_uri"] = application.backchannel_logout_uri
        # What this server registers whatever the client asked for, since it issues no
        # sid; reporting it is how a client learns its request was not honoured.
        data["backchannel_logout_session_required"] = False
    return data


# RFC 7517/7518 private key members. Registration and Application.clean()
# refuse private material, but a manually edited row must never be echoed
# back through the management endpoint.
_PRIVATE_JWK_MEMBERS = frozenset({"d", "k", "p", "q", "dp", "dq", "qi", "oth"})


def _stored_jwks_for_response(application):
    """The stored client JWKS as a response-safe object, or None to omit it.

    Registration validated the value, but a corrupted or manually edited row
    must degrade safely: unparseable JSON omits the field instead of raising a
    500, and any key carrying private members is dropped rather than disclosed.
    """
    try:
        parsed = json.loads(application.client_jwks)
    except ValueError:
        log.warning(
            "Stored client_jwks for application %s is not valid JSON; omitting jwks "
            "from the registration response",
            application.client_id,
        )
        return None
    keys = parsed.get("keys") if isinstance(parsed, dict) else None
    if not isinstance(keys, list):
        return None
    public_keys = []
    for key in keys:
        if not isinstance(key, dict):
            continue
        if _PRIVATE_JWK_MEMBERS.intersection(key):
            log.warning(
                "Stored client_jwks for application %s contains private key material; "
                "omitting that key from the registration response",
                application.client_id,
            )
            continue
        public_keys.append(key)
    if not public_keys:
        return None
    return {"keys": public_keys}


def _dot_grant_to_rfc_grant_types(dot_grant: str) -> list[str]:
    """Return the RFC 7591 grant_types list for a DOT grant type constant."""
    if dot_grant == AbstractApplication.GRANT_OPENID_HYBRID:
        # The hybrid grant serves both grants its response types need, and
        # refresh_token like authorization_code below.
        return ["authorization_code", "implicit", "refresh_token"]
    reverse_map = {v: k for k, v in GRANT_TYPE_MAP.items()}
    rfc_grant = reverse_map.get(dot_grant, dot_grant)
    # For authorization_code, also surface refresh_token per RFC 7591 convention
    result = [rfc_grant]
    if dot_grant == "authorization-code":
        result.append("refresh_token")
    return result


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class DynamicClientRegistrationView(View):
    """
    RFC 7591 — Dynamic Client Registration endpoint.

    POST /register/

    The view is ``csrf_exempt`` because DCR is an API endpoint typically called
    with no cookies at all (anonymous or ``Authorization``-header credentials).
    CSRF protection for session-cookie-authenticated requests is enforced by
    ``IsAuthenticatedDCRPermission`` in the permission layer instead; custom
    permission classes that rely on Django's session authentication should do
    the same (see ``oauth2_provider.authorization_server.dcr.enforce_csrf``).
    """

    def dispatch(self, request, *args, **kwargs):
        if not oauth2_settings.DCR_ENABLED:
            return JsonResponse({"error": "not_found"}, status=404)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Permission check
        if not _check_permissions(request):
            return _error_response(
                "access_denied",
                "Authentication required to register a client",
                status=401,
            )

        data, err = _parse_metadata(request.body)
        if err:
            return err

        app_kwargs, err = _build_application_kwargs(data)
        if err:
            return err

        Application = get_application_model()
        user = request.user if request.user.is_authenticated else None
        application = Application(
            user=user,
            registration_source=Application.RegistrationSource.DCR,
            **app_kwargs,
        )

        # Capture the raw secret before save() hashes it. A private_key_jwt
        # client authenticates with its key, never the secret, so none is
        # returned for it (RFC 7591 section 3.2.1 makes client_secret optional).
        include_secret = (
            application.client_type == "confidential"
            and application.token_endpoint_auth_method != Application.TOKEN_AUTH_METHOD_PRIVATE_KEY_JWT
        )
        raw_secret = application.client_secret if include_secret else None

        try:
            application.full_clean()
        except ValidationError as exc:
            return _error_response("invalid_client_metadata", _validation_error_description(exc))

        with transaction.atomic():
            application.save()
            raw_registration_token = _issue_registration_token(application, user)

        response_data = _application_to_response(application, raw_registration_token, request)
        if raw_secret:
            response_data["client_secret"] = raw_secret
            # RFC 7591 section 3.2.1 makes client_secret_expires_at REQUIRED
            # whenever client_secret is issued; 0 means it never expires, which
            # holds for every secret the toolkit issues.
            response_data["client_secret_expires_at"] = 0

        return JsonResponse(response_data, status=201)


@dataclass(frozen=True)
class _AuthenticatedRegistration:
    """A management request that presented a valid registration access token.

    ``presented_token`` is the raw token from the ``Authorization`` header. It is
    carried alongside the row because under ``COMPLIANT_BCP_RFC9700_TOKEN_STORAGE``
    the ``token`` column is blank, so the request itself is the only remaining
    source of the value the RFC 7592 read response has to echo back.
    """

    application: AbstractApplication
    registration_token: AbstractAccessToken
    presented_token: str


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class DynamicClientRegistrationManagementView(View):
    """
    RFC 7592 — Client Configuration Endpoint.

    GET/PUT/DELETE /register/{client_id}/
    """

    def dispatch(self, request, *args, **kwargs):
        if not oauth2_settings.DCR_ENABLED:
            return JsonResponse({"error": "not_found"}, status=404)
        return super().dispatch(request, *args, **kwargs)

    def _authenticate_registration_request(
        self, request: HttpRequest, client_id: str
    ) -> _AuthenticatedRegistration | HttpResponse:
        """
        Validate Bearer token, check scope, check client_id match.

        Returns the authenticated registration, or the error response to send.
        """
        presented_token = parse_bearer_token(request.META.get("HTTP_AUTHORIZATION", ""))
        if presented_token is None:
            return _error_response(
                "invalid_token",
                "Registration access token required",
                status=401,
            )

        token_checksum = hashlib.sha256(presented_token.encode("utf-8")).hexdigest()
        AccessToken = get_access_token_model()
        try:
            token = AccessToken.objects.get(token_checksum=token_checksum)
        except AccessToken.DoesNotExist:
            return _error_response(
                "invalid_token",
                "Invalid registration access token",
                status=401,
            )

        if not token.is_valid([oauth2_settings.DCR_REGISTRATION_SCOPE]):
            return _error_response(
                "invalid_token",
                "Registration access token is expired or invalid",
                status=401,
            )

        application = token.application
        if application is None or application.client_id != client_id:
            # 401 rather than 403: per RFC 6750 the invalid_token error code
            # belongs on a 401 challenge, and the token simply isn't valid for
            # this registration URI. This also avoids confirming whether the
            # requested client_id exists.
            return _error_response("invalid_token", "Token does not match client_id", status=401)

        # RFC 7592 management only applies to dynamically registered clients.
        # This stops a regular access token that happens to carry
        # DCR_REGISTRATION_SCOPE (e.g. through scope misconfiguration) from
        # being used to reconfigure or delete a manually provisioned
        # application. This must be an equality check against DCR: the other
        # registration_source values ("manual", "cimd") are truthy strings, so
        # a "not application.registration_source" test would let every
        # application through the management endpoint.
        if application.registration_source != application.RegistrationSource.DCR:
            return _error_response(
                "invalid_token",
                "Token was not issued by the registration endpoint",
                status=401,
            )

        return _AuthenticatedRegistration(application, token, presented_token)

    def get(self, request: HttpRequest, client_id: str, *args, **kwargs) -> HttpResponse:
        auth = self._authenticate_registration_request(request, client_id)
        if isinstance(auth, HttpResponse):
            return auth

        return JsonResponse(_application_to_response(auth.application, auth.presented_token, request))

    def put(self, request: HttpRequest, client_id: str, *args, **kwargs) -> HttpResponse:
        auth = self._authenticate_registration_request(request, client_id)
        if isinstance(auth, HttpResponse):
            return auth

        application = auth.application
        response_token = auth.presented_token

        data, err = _parse_metadata(request.body)
        if err:
            return err

        app_kwargs, err = _build_application_kwargs(
            data,
            client_secret=application.client_secret,
            client_secret_is_hashed=application._client_secret_is_hashed(application.client_secret),
            current_algorithm=application.algorithm,
        )
        if err:
            return err

        for field, value in app_kwargs.items():
            setattr(application, field, value)

        try:
            application.full_clean()
        except ValidationError as exc:
            return _error_response("invalid_client_metadata", _validation_error_description(exc))

        with transaction.atomic():
            application.save()

            if oauth2_settings.DCR_ROTATE_REGISTRATION_TOKEN_ON_UPDATE:
                user = application.user
                response_token = _issue_registration_token(application, user)
                auth.registration_token.delete()

        return JsonResponse(_application_to_response(application, response_token, request))

    def delete(self, request: HttpRequest, client_id: str, *args, **kwargs) -> HttpResponse:
        auth = self._authenticate_registration_request(request, client_id)
        if isinstance(auth, HttpResponse):
            return auth

        auth.application.delete()
        return HttpResponse(status=204)
