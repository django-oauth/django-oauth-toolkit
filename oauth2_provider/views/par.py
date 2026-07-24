import secrets

from django import http
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from oauthlib.common import Request as OAuthlibRequest

from oauth2_provider.compat import login_not_required
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.models import create_pushed_authorization_request
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.mixins import OAuthLibMixin


# Request URIs use the IANA-registered URN sub-namespace (RFC 9126 §2.2 / §9.3).
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

# Parameters that authenticate the client at a token-style endpoint. They are
# relied upon only for client authentication and are not part of the authorization
# request itself (RFC 9126 §2.1), so they are never stored on the pushed request.
CLIENT_AUTH_PARAMETERS = frozenset(
    {
        "client_secret",
        "client_assertion",
        "client_assertion_type",
    }
)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class PushedAuthorizationRequestView(OAuthLibMixin, View):
    """
    Implements the Pushed Authorization Request (PAR) endpoint as defined in
    :rfc:`9126`.

    A client authenticates and POSTs the parameters that comprise an
    authorization request; the server validates them and returns a single-use
    ``request_uri`` that the client subsequently presents at the authorization
    endpoint in place of the individual parameters.
    """

    # POST-only: the base View returns 405 for any other method (RFC 9126 §2.3).
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        if not oauth2_settings.PAR_ENABLED:
            return self._error_response("invalid_request", "PAR is not enabled.", status=400)

        # RFC 9126 §2.1 step 2: a pushed request must not itself carry a request_uri.
        if "request_uri" in request.POST:
            return self._error_response(
                "invalid_request",
                "The request_uri parameter must not be provided to the PAR endpoint.",
                status=400,
            )

        # JWT-Secured Authorization Request objects (RFC 9126 §3 / RFC 9101) are not
        # supported yet; reject rather than silently ignore a signed request.
        if "request" in request.POST:
            return self._error_response(
                "invalid_request",
                "Request objects (the 'request' parameter) are not supported.",
                status=400,
            )

        core = self.get_oauthlib_core()

        # RFC 9126 §2.1 step 1: authenticate the client exactly as at the token
        # endpoint. Confidential clients authenticate; public clients (e.g. PKCE)
        # are identified by client_id.
        client = self._authenticate_client(core, request)
        if client is None:
            return self._error_response("invalid_client", "Client authentication failed.", status=401)

        # RFC 9126 §2.1 step 3: validate the pushed parameters as an authorization
        # request. Parameters arrive in the POST body; oauthlib merges the body into
        # its Request, so the existing authorization validation applies unchanged.
        try:
            core.validate_authorization_request(request)
        except OAuthToolkitError as error:
            return self._error_from_oauthlib(error)

        # The request URI is bound to the authenticated client (RFC 9126 §2.2). The
        # client_id is a required authorization-request parameter, so it must match.
        client_id = request.POST.get("client_id")
        if client_id and client.client_id != client_id:
            return self._error_response(
                "invalid_request",
                "The client_id does not match the authenticated client.",
                status=400,
            )

        parameters = self._collect_parameters(request)
        request_uri = REQUEST_URI_PREFIX + secrets.token_urlsafe(32)
        lifetime = oauth2_settings.PAR_REQUEST_URI_LIFETIME_SECONDS
        create_pushed_authorization_request(
            request_uri=request_uri,
            client_id=client.client_id,
            parameters=parameters,
            expires_in=lifetime,
        )

        return self._json_response({"request_uri": request_uri, "expires_in": lifetime}, status=201)

    def _authenticate_client(self, core, request):
        """
        Authenticate the request's client, returning the client instance or ``None``.

        Confidential clients are authenticated with their credentials; public
        clients that cannot authenticate are accepted on client_id alone, mirroring
        how the authorization-code grant treats public clients.
        """
        uri, http_method, body, headers = core._extract_params(request)
        oauthlib_request = OAuthlibRequest(uri, http_method=http_method, body=body, headers=headers)
        validator = core.server.request_validator

        if validator.authenticate_client(oauthlib_request):
            return oauthlib_request.client

        client_id = oauthlib_request.client_id
        if client_id and validator.authenticate_client_id(client_id, oauthlib_request):
            return oauthlib_request.client

        return None

    def _collect_parameters(self, request):
        """
        Build the JSON-serialisable mapping of authorization-request parameters to
        store, dropping client-authentication parameters. Repeated ``resource``
        values (RFC 8707) are preserved as a list; all other parameters keep their
        last value, matching ``OAuthLibCore.extract_body``.
        """
        parameters = {}
        for key in request.POST:
            if key in CLIENT_AUTH_PARAMETERS:
                continue
            values = request.POST.getlist(key)
            parameters[key] = values if key == "resource" else values[-1]
        return parameters

    def _error_from_oauthlib(self, error):
        oauthlib_error = error.oauthlib_error
        error_code = getattr(oauthlib_error, "error", None) or "invalid_request"
        description = getattr(oauthlib_error, "description", "") or ""
        status = getattr(oauthlib_error, "status_code", 400) or 400
        return self._error_response(error_code, description, status=status)

    def _error_response(self, error, description, status):
        body = {"error": error}
        if description:
            body["error_description"] = description
        return self._json_response(body, status=status)

    def _json_response(self, data, status):
        response = http.JsonResponse(data, status=status)
        # RFC 9126 §2.2 / §2.3: responses carrying a request_uri or error must not be cached.
        response["Cache-Control"] = "no-cache, no-store"
        return response
