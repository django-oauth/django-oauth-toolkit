"""
Views implementing OAuth 2.0 Dynamic Client Registration Protocol.

RFC 7591 — POST /register/
RFC 7592 — GET/PUT/DELETE /register/{client_id}/
"""

import hashlib
import json
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


def _error_response(error, description, status=400):
    return JsonResponse({"error": error, "error_description": description}, status=status)


def _check_permissions(request):
    """Run all DCR_REGISTRATION_PERMISSION_CLASSES; return True if all pass."""
    permission_classes = oauth2_settings.DCR_REGISTRATION_PERMISSION_CLASSES
    for cls in permission_classes:
        instance = cls()
        if not instance.has_permission(request):
            return False
    return True


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

    # client_name
    if "client_name" in data:
        kwargs["name"] = data["client_name"]

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

    # token_endpoint_auth_method → client_type
    SUPPORTED_AUTH_METHODS = ("none", "client_secret_basic", "client_secret_post")
    auth_method = data.get("token_endpoint_auth_method", "client_secret_basic")
    if auth_method not in SUPPORTED_AUTH_METHODS:
        return None, _error_response(
            "invalid_client_metadata",
            f"Unsupported token_endpoint_auth_method: {auth_method!r}. "
            f"Supported values: {', '.join(SUPPORTED_AUTH_METHODS)}",
        )
    if auth_method == "none":
        kwargs["client_type"] = "public"
    else:
        kwargs["client_type"] = "confidential"

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
    data = {
        "client_id": application.client_id,
        "redirect_uris": application.redirect_uris.split() if application.redirect_uris else [],
        "grant_types": _dot_grant_to_rfc_grant_types(application.authorization_grant_type),
        "token_endpoint_auth_method": (
            "none" if application.client_type == "public" else "client_secret_basic"
        ),
        "registration_access_token": registration_token.token,
        "registration_client_uri": request.build_absolute_uri(
            reverse("oauth2_provider:dcr-register-management", kwargs={"client_id": application.client_id})
        ),
    }
    if application.name:
        data["client_name"] = application.name
    return data


def _dot_grant_to_rfc_grant_types(dot_grant):
    """Return the RFC 7591 grant_types list for a DOT grant type constant."""
    reverse_map = {v: k for k, v in GRANT_TYPE_MAP.items()}
    rfc_grant = reverse_map.get(dot_grant, dot_grant)
    # For authorization_code, also surface refresh_token per RFC 7591 convention
    result = [rfc_grant]
    if dot_grant == "authorization-code":
        result.append("refresh_token")
    return result


@method_decorator(login_not_required, name="dispatch")
class DynamicClientRegistrationView(View):
    """
    RFC 7591 — Dynamic Client Registration endpoint.

    POST /register/
    """

    def dispatch(self, request, *args, **kwargs):
        if not oauth2_settings.DCR_ENABLED:
            return JsonResponse({"error": "not_found"}, status=404)
        if not request.user.is_authenticated or request.META.get("HTTP_AUTHORIZATION"):
            request._dont_enforce_csrf_checks = True
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
        application = Application(user=user, **app_kwargs)

        # Capture the raw secret before save() hashes it
        raw_secret = application.client_secret if application.client_type == "confidential" else None

        try:
            application.full_clean()
        except ValidationError as exc:
            return _error_response("invalid_client_metadata", str(exc))

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
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Bearer "):
            return None, _error_response(
                "invalid_token",
                "Registration access token required",
                status=401,
            )

        raw_token = auth_header[len("Bearer ") :]
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
            return None, _error_response("invalid_token", "Token does not match client_id", status=403)

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
            return _error_response("invalid_client_metadata", str(exc))

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
