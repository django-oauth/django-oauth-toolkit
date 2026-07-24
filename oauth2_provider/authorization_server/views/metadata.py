"""Authorization-server metadata (RFC 8414) and the shared discovery helpers.

Also home to the ``bcp_filter_*`` helpers and ``ServerMetadataViewMixin`` reused
by the OpenID Connect discovery document
(:class:`oauth2_provider.authorization_server.oidc.views.ConnectDiscoveryInfoView`).
"""

from urllib.parse import urlparse

from django.http import JsonResponse
from django.urls import NoReverseMatch, reverse
from django.utils.decorators import method_decorator
from django.views.generic import View

from oauth2_provider.core.compat import login_not_required
from oauth2_provider.models import AbstractGrant
from oauth2_provider.settings import oauth2_settings


def _is_implicit_response_type(response_type):
    """
    Whether a response type is an implicit-grant (front-channel) response type per
    RFC 9700 §2.1.2: it issues a ``token``/``id_token`` directly without an
    authorization ``code``. Response types are space-separated *sets*, so the token
    order does not matter (``"id_token token"`` == ``"token id_token"``); hybrid
    response types (which include ``code``) are not implicit.
    """
    values = set(response_type.split())
    return "code" not in values and bool(values & {"token", "id_token"})


def bcp_filter_response_types(response_types):
    """
    Drop implicit response types from a discovery list when the implicit-grant gate
    (``COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT``) is enabled, so discovery matches
    what the server will actually accept. Shared by the RFC 8414 and OIDC discovery
    documents.
    """
    if not oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT:
        return list(response_types)
    return [rt for rt in response_types if not _is_implicit_response_type(rt)]


def bcp_filter_code_challenge_methods(methods):
    """
    Drop the ``plain`` PKCE method when its gate
    (``COMPLIANT_BCP_RFC9700_PKCE_METHOD``) is enabled.
    """
    if not oauth2_settings.COMPLIANT_BCP_RFC9700_PKCE_METHOD:
        return list(methods)
    return [m for m in methods if m != "plain"]


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

        # RFC 9700: stop advertising grant/response types that the corresponding
        # COMPLIANT_BCP_RFC9700_* gate has enabled, so discovery reflects what
        # the server will actually accept.
        response_types = bcp_filter_response_types(oauth2_settings.OAUTH2_RESPONSE_TYPES_SUPPORTED)
        grant_types = list(oauth2_settings.OAUTH2_GRANT_TYPES_SUPPORTED)
        if oauth2_settings.COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT:
            grant_types = [gt for gt in grant_types if gt != "implicit"]
        if oauth2_settings.COMPLIANT_BCP_RFC9700_PASSWORD_GRANT:
            grant_types = [gt for gt in grant_types if gt != "password"]

        data = {
            "issuer": issuer_url,
            "response_types_supported": response_types,
            "grant_types_supported": grant_types,
            "scopes_supported": sorted(scopes.get_available_scopes()),
            # draft-ietf-oauth-client-id-metadata-document: signal whether a
            # client may use its metadata-document URL as its client_id.
            "client_id_metadata_document_supported": oauth2_settings.CIMD_ENABLED,
        }
        # RFC 9207: advertise that we set the `iss` authorization-response parameter
        # once the mix-up defense is enforced (gate enabled).
        if oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS:
            data["authorization_response_iss_parameter_supported"] = True

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

        # The DCR URL pattern is always registered while the view itself 404s
        # when DCR is off, so gate the advertisement on the setting rather
        # than on reverse() succeeding.
        if oauth2_settings.DCR_ENABLED:
            registration_url = self._get_endpoint_url(request, "dcr-register")
            if registration_url:
                data["registration_endpoint"] = registration_url

        # Capability fields describe a specific endpoint, so only advertise them
        # when that endpoint is actually present.
        if "authorization_endpoint" in data:
            # RFC 9700 §2.1.1: drop "plain" from discovery when it is no longer accepted.
            data["code_challenge_methods_supported"] = bcp_filter_code_challenge_methods(
                [key for key, _ in AbstractGrant.CODE_CHALLENGE_METHODS]
            )
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
