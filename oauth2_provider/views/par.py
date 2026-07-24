from django import http
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from oauth2_provider import par
from oauth2_provider.compat import login_not_required
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.views.mixins import OAuthLibMixin


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

    This view is a thin HTTP adapter; the request handling lives in
    :mod:`oauth2_provider.par`.
    """

    # POST-only: the base View returns 405 for any other method (RFC 9126 §2.3).
    http_method_names = ["post"]

    def dispatch(self, request, *args, **kwargs):
        if not oauth2_settings.PAR_ENABLED:
            # A disabled endpoint behaves as absent for *every* method (matching the
            # DCR endpoint when DCR_ENABLED is off), rather than returning an OAuth
            # error — or a 405 for non-POST methods — from a supported endpoint.
            return http.JsonResponse({"error": "not_found"}, status=404)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
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
        client = par.authenticate_par_client(core, request)
        if client is None:
            return self._error_response("invalid_client", "Client authentication failed.", status=401)

        # Bind the request to the authenticated client (RFC 9126 §2.2) *before*
        # validating it, so a client cannot submit an arbitrary client_id and observe
        # validation differences (e.g. whether another client exists or has a given
        # redirect_uri). client_id is a required authorization-request parameter.
        client_id = request.POST.get("client_id")
        if client_id and client.client_id != client_id:
            return self._error_response(
                "invalid_request",
                "The client_id does not match the authenticated client.",
                status=400,
            )

        # RFC 9126 §2.1 step 3: validate the pushed parameters as an authorization
        # request. Parameters arrive in the POST body; oauthlib merges the body into
        # its Request, so the existing authorization validation applies unchanged.
        try:
            core.validate_authorization_request(request)
        except OAuthToolkitError as error:
            return self._error_from_oauthlib(error)

        parameters = par.collect_pushed_parameters(request)
        request_uri, expires_in = par.store_pushed_request(client.client_id, parameters)
        return self._json_response({"request_uri": request_uri, "expires_in": expires_in}, status=201)

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
        response = self._json_response(body, status=status)
        if status == 401:
            # RFC 6749 §5.2 / RFC 9126 §2.3: a 401 client-authentication failure must
            # carry a WWW-Authenticate header. Match the token endpoint's oauthlib format.
            challenge = 'Bearer error="{}"'.format(error)
            if description:
                challenge += ', error_description="{}"'.format(description)
            response["WWW-Authenticate"] = challenge
        return response

    def _json_response(self, data, status):
        response = http.JsonResponse(data, status=status)
        # RFC 9126 §2.2 / §2.3: responses carrying a request_uri or error must not be cached.
        response["Cache-Control"] = "no-cache, no-store"
        return response
