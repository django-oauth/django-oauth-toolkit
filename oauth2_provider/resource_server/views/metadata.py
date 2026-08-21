"""Resource-server metadata (RFC 9728 Protected Resource Metadata)."""

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.generic import View

from oauth2_provider.core.compat import login_not_required
from oauth2_provider.settings import oauth2_settings


@method_decorator(login_not_required, name="dispatch")
class OAuthProtectedResourceMetadataView(View):
    """
    View for RFC 9728 OAuth 2.0 Protected Resource Metadata.
    https://www.rfc-editor.org/rfc/rfc9728

    Publishes the protected resource's metadata document at
    ``/.well-known/oauth-protected-resource`` so clients can discover which
    authorization server(s) issue tokens for it, the scopes and bearer methods it
    accepts, and human-readable details. The endpoint is always available,
    regardless of whether OIDC is enabled.

    Every advertised value is produced by a ``get_*`` method that defaults to the
    corresponding ``OAUTH2_PROTECTED_RESOURCE_*`` setting but can be overridden in a
    subclass, so a deployment serving several protected resources (the RFC 9728
    path-component form) can subclass and customise per resource.
    """

    def get_resource(self, request):
        """The REQUIRED ``resource`` identifier for this protected resource."""
        return oauth2_settings.oauth2_resource_identifier(request)

    def get_authorization_servers(self, request):
        """The ``authorization_servers`` list (omitted from the document when empty)."""
        return oauth2_settings.oauth2_resource_authorization_servers(request)

    def get_scopes_supported(self):
        """The ``scopes_supported`` list, from the configured scopes backend."""
        scopes_class = oauth2_settings.SCOPES_BACKEND_CLASS
        scopes = scopes_class()
        return sorted(scopes.get_available_scopes())

    def get_bearer_methods_supported(self):
        """The ``bearer_methods_supported`` list."""
        return oauth2_settings.OAUTH2_PROTECTED_RESOURCE_BEARER_METHODS_SUPPORTED

    def get_resource_name(self):
        """Human-readable ``resource_name`` (omitted when empty)."""
        return oauth2_settings.OAUTH2_PROTECTED_RESOURCE_NAME

    def get_resource_documentation(self):
        """``resource_documentation`` URL (omitted when empty)."""
        return oauth2_settings.OAUTH2_PROTECTED_RESOURCE_DOCUMENTATION

    def get_resource_policy_uri(self):
        """``resource_policy_uri`` URL (omitted when empty)."""
        return oauth2_settings.OAUTH2_PROTECTED_RESOURCE_POLICY_URI

    def get_resource_tos_uri(self):
        """``resource_tos_uri`` URL (omitted when empty)."""
        return oauth2_settings.OAUTH2_PROTECTED_RESOURCE_TOS_URI

    def get(self, request, *args, **kwargs):
        data = {"resource": self.get_resource(request)}

        authorization_servers = self.get_authorization_servers(request)
        if authorization_servers:
            data["authorization_servers"] = authorization_servers

        data["scopes_supported"] = self.get_scopes_supported()
        data["bearer_methods_supported"] = self.get_bearer_methods_supported()

        # Optional human-readable fields are only advertised when configured.
        for key, value in [
            ("resource_name", self.get_resource_name()),
            ("resource_documentation", self.get_resource_documentation()),
            ("resource_policy_uri", self.get_resource_policy_uri()),
            ("resource_tos_uri", self.get_resource_tos_uri()),
        ]:
            if value:
                data[key] = value

        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response
