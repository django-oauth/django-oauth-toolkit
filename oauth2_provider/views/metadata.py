from urllib.parse import urlparse

from django.http import JsonResponse
from django.urls import NoReverseMatch, reverse
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

    def _get_endpoint_url(self, request, view_name, required=False):
        """Build an absolute endpoint URL.

        Returns ``None`` when the URL name is not registered, so optional
        endpoints can simply be omitted. Pass ``required=True`` to fail fast
        (let ``NoReverseMatch`` propagate) for endpoints that must be present,
        rather than emitting a ``null`` value that hides misconfiguration.
        """
        try:
            path = reverse(f"oauth2_provider:{view_name}")
        except NoReverseMatch:
            if required:
                raise
            return None
        issuer = oauth2_settings.OIDC_ISS_ENDPOINT
        if not issuer:
            return request.build_absolute_uri(path)
        parsed = urlparse(issuer)
        host = parsed.scheme + "://" + parsed.netloc
        return f"{host}{path}"


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

        auth_methods = oauth2_settings.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED

        data = {
            "issuer": issuer_url,
            "response_types_supported": oauth2_settings.OAUTH2_RESPONSE_TYPES_SUPPORTED,
            "grant_types_supported": oauth2_settings.OAUTH2_GRANT_TYPES_SUPPORTED,
            "scopes_supported": sorted(scopes.get_available_scopes()),
            # draft-ietf-oauth-client-id-metadata-document: signal whether a
            # client may use its metadata-document URL as its client_id.
            "client_id_metadata_document_supported": oauth2_settings.CIMD_ENABLED,
        }

        # Endpoint URLs are resolved via reverse() and omitted if not registered
        for key, view_name in [
            ("authorization_endpoint", "authorize"),
            ("token_endpoint", "token"),
            ("revocation_endpoint", "revoke-token"),
            ("introspection_endpoint", "introspect"),
        ]:
            url = self._get_endpoint_url(request, view_name)
            if url:
                data[key] = url

        # Capability fields describe a specific endpoint, so only advertise them
        # when that endpoint is actually present.
        if "authorization_endpoint" in data:
            data["code_challenge_methods_supported"] = [
                key for key, _ in AbstractGrant.CODE_CHALLENGE_METHODS
            ]
        if "token_endpoint" in data:
            data["token_endpoint_auth_methods_supported"] = auth_methods
        if "revocation_endpoint" in data:
            data["revocation_endpoint_auth_methods_supported"] = auth_methods
        if "introspection_endpoint" in data:
            data["introspection_endpoint_auth_methods_supported"] = auth_methods

        if oauth2_settings.OIDC_ENABLED and oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            jwks_url = self._get_endpoint_url(request, "jwks-info")
            if jwks_url:
                data["jwks_uri"] = jwks_url

        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


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
