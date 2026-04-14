from urllib.parse import urlparse

from django.http import JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import View

from ..compat import login_not_required
from ..models import AbstractGrant
from ..settings import oauth2_settings


class ServerMetadataViewMixin:
    """
    Shared URL-building logic for server metadata discovery views.
    Handles both request-relative and OIDC_ISS_ENDPOINT-anchored URLs.
    """

    def _get_endpoint_url(self, request, view_name):
        """Build an absolute endpoint URL using the configured issuer or request."""
        issuer = oauth2_settings.OIDC_ISS_ENDPOINT
        if not issuer:
            return request.build_absolute_uri(reverse(f"oauth2_provider:{view_name}"))
        parsed = urlparse(issuer)
        host = parsed.scheme + "://" + parsed.netloc
        return "{}{}".format(host, reverse(f"oauth2_provider:{view_name}"))


@method_decorator(login_not_required, name="dispatch")
class OAuthServerMetadataView(ServerMetadataViewMixin, View):
    """
    View for RFC 8414 OAuth 2.0 Authorization Server Metadata.
    https://www.rfc-editor.org/rfc/rfc8414
    Available regardless of whether OIDC is enabled.
    """

    def get(self, request, *args, **kwargs):
        issuer_url = oauth2_settings.oauth2_metadata_issuer(request)

        scopes_class = oauth2_settings.SCOPES_BACKEND_CLASS
        scopes = scopes_class()

        data = {
            "issuer": issuer_url,
            "authorization_endpoint": self._get_endpoint_url(request, "authorize"),
            "token_endpoint": self._get_endpoint_url(request, "token"),
            "revocation_endpoint": self._get_endpoint_url(request, "revoke-token"),
            "introspection_endpoint": self._get_endpoint_url(request, "introspect"),
            "response_types_supported": oauth2_settings.OAUTH2_RESPONSE_TYPES_SUPPORTED,
            "grant_types_supported": oauth2_settings.OAUTH2_GRANT_TYPES_SUPPORTED,
            "scopes_supported": sorted(scopes.get_available_scopes()),
            "token_endpoint_auth_methods_supported": oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
            "code_challenge_methods_supported": [key for key, _ in AbstractGrant.CODE_CHALLENGE_METHODS],
        }
        if oauth2_settings.OIDC_ENABLED and oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            data["jwks_uri"] = self._get_endpoint_url(request, "jwks-info")

        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response
