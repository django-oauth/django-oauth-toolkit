"""
Views implementing OAuth 2.0 Dynamic Client Registration Protocol.

RFC 7591 — POST /register/
RFC 7592 — GET/PUT/DELETE /register/{client_id}/
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from ..compat import login_not_required
from ..models import get_access_token_model, get_application_model
from ..settings import oauth2_settings
from ..utils import parse_bearer_token


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

# DOT grant types for which Application.clean() requires redirect_uris
REDIRECT_REQUIRED_GRANT_TYPES = {"authorization-code", "implicit"}


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


def _resolve_grant_type(grant_types):
    """
    Resolve RFC 7591 grant_types list to a single DOT grant type constant.

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

    if len(meaningful) > 1:
        return None, _error_response(
            "invalid_client_metadata",
            "DOT only supports one grant type per application; "
            "multiple non-refresh_token grant types are not supported",
        )

    grant_type = meaningful[0]
    dot_grant = GRANT_TYPE_MAP.get(grant_type)
    if dot_grant is None:
        return None, _error_response(
            "invalid_client_metadata",
            f"Unsupported grant_type: {grant_type!r}",
        )
    return dot_grant, None


def _build_application_kwargs(data):
    """
    Convert RFC 7591 metadata dict to Application field kwargs.

    Returns (kwargs_dict, error_response).
    """
    kwargs = {}

    # redirect_uris
    redirect_uris = data.get("redirect_uris", [])
    if not isinstance(redirect_uris, list):
        return None, _error_response("invalid_client_metadata", "redirect_uris must be an array")
    if not all(isinstance(uri, str) for uri in redirect_uris):
        return None, _error_response("invalid_client_metadata", "Each redirect_uri must be a string")
    kwargs["redirect_uris"] = " ".join(redirect_uris)

    # client_name — always set so a request is a full replacement of the
    # metadata (RFC 7592 §2.2): on PUT an omitted client_name resets
    # Application.name to empty, consistent with the other fields below. On
    # POST this is equivalent to the model's blank default.
    kwargs["name"] = data.get("client_name", "")

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

    # Fail early with RFC 7591 field names/values; deferring to
    # Application.clean() would surface DOT's internal grant type constants
    # (e.g. "authorization-code") in the error_description.
    if dot_grant in REDIRECT_REQUIRED_GRANT_TYPES and not redirect_uris:
        rfc_grant = _dot_grant_to_rfc_grant_types(dot_grant)[0]
        return None, _error_response(
            "invalid_client_metadata",
            f"redirect_uris is required for grant type {rfc_grant!r}",
        )

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

    return kwargs, None


def _issue_registration_token(application, user):
    """
    Create and return a new registration AccessToken for *application*.

    Token scope is ``oauth2_settings.DCR_REGISTRATION_SCOPE``.
    Expiry: far-future (year 9999) when ``DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS`` is None,
    otherwise ``now + DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS`` seconds.
    """
    from ..generators import generate_client_secret  # reuse secret-quality token generator

    AccessToken = get_access_token_model()

    expire_seconds = oauth2_settings.DCR_REGISTRATION_TOKEN_EXPIRE_SECONDS
    if expire_seconds is None:
        expires = datetime(9999, 12, 31, 23, 59, 59, tzinfo=dt_timezone.utc)
    else:
        expires = timezone.now() + timedelta(seconds=expire_seconds)

    token = AccessToken.objects.create(
        application=application,
        user=user,
        token=generate_client_secret(),
        expires=expires,
        scope=oauth2_settings.DCR_REGISTRATION_SCOPE,
    )
    return token


def _application_to_response(application, registration_token, request):
    """Build the RFC 7591 response dict for *application*."""
    # Registrations persist the method explicitly; legacy rows (blank field)
    # keep the old client_type-based inference.
    auth_method = application.token_endpoint_auth_method or (
        "none" if application.client_type == "public" else "client_secret_basic"
    )
    data = {
        "client_id": application.client_id,
        "redirect_uris": application.redirect_uris.split() if application.redirect_uris else [],
        "grant_types": _dot_grant_to_rfc_grant_types(application.authorization_grant_type),
        "token_endpoint_auth_method": auth_method,
        "registration_access_token": registration_token.token,
        "registration_client_uri": request.build_absolute_uri(
            reverse("oauth2_provider:dcr-register-management", kwargs={"client_id": application.client_id})
        ),
    }
    if application.name:
        data["client_name"] = application.name
    if application.client_jwks:
        jwks = _stored_jwks_for_response(application)
        if jwks is not None:
            data["jwks"] = jwks
    if application.client_jwks_uri:
        data["jwks_uri"] = application.client_jwks_uri
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


def _dot_grant_to_rfc_grant_types(dot_grant):
    """Return the RFC 7591 grant_types list for a DOT grant type constant."""
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
    the same (see ``oauth2_provider.dcr.enforce_csrf``).
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
            registration_token = _issue_registration_token(application, user)

        response_data = _application_to_response(application, registration_token, request)
        if raw_secret:
            response_data["client_secret"] = raw_secret

        return JsonResponse(response_data, status=201)


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

    def _get_application_from_registration_token(self, request, client_id):
        """
        Validate Bearer token, check scope, check client_id match.

        Returns (application, registration_token) or (None, error_response).
        """
        raw_token = parse_bearer_token(request.META.get("HTTP_AUTHORIZATION", ""))
        if raw_token is None:
            return None, _error_response(
                "invalid_token",
                "Registration access token required",
                status=401,
            )

        token_checksum = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        AccessToken = get_access_token_model()
        try:
            token = AccessToken.objects.get(token_checksum=token_checksum)
        except AccessToken.DoesNotExist:
            return None, _error_response(
                "invalid_token",
                "Invalid registration access token",
                status=401,
            )

        if not token.is_valid([oauth2_settings.DCR_REGISTRATION_SCOPE]):
            return None, _error_response(
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
            return None, _error_response("invalid_token", "Token does not match client_id", status=401)

        # RFC 7592 management only applies to dynamically registered clients.
        # This stops a regular access token that happens to carry
        # DCR_REGISTRATION_SCOPE (e.g. through scope misconfiguration) from
        # being used to reconfigure or delete a manually provisioned
        # application. This must be an equality check against DCR: the other
        # registration_source values ("manual", "cimd") are truthy strings, so
        # a "not application.registration_source" test would let every
        # application through the management endpoint.
        if application.registration_source != application.RegistrationSource.DCR:
            return None, _error_response(
                "invalid_token",
                "Token was not issued by the registration endpoint",
                status=401,
            )

        return application, token

    def get(self, request, client_id, *args, **kwargs):
        application, result = self._get_application_from_registration_token(request, client_id)
        if application is None:
            return result  # error response

        registration_token = result
        return JsonResponse(_application_to_response(application, registration_token, request))

    def put(self, request, client_id, *args, **kwargs):
        application, result = self._get_application_from_registration_token(request, client_id)
        if application is None:
            return result

        registration_token = result

        data, err = _parse_metadata(request.body)
        if err:
            return err

        app_kwargs, err = _build_application_kwargs(data)
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
                new_token = _issue_registration_token(application, user)
                registration_token.delete()
                registration_token = new_token

        return JsonResponse(_application_to_response(application, registration_token, request))

    def delete(self, request, client_id, *args, **kwargs):
        application, result = self._get_application_from_registration_token(request, client_id)
        if application is None:
            return result

        application.delete()
        return HttpResponse(status=204)
