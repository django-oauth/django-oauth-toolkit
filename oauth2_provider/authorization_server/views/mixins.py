"""Authorization-server view mixin.

``AuthorizationServerViewMixin`` provides the oauthlib response-building helpers
used by the authorization, token, revocation, device-authorization and userinfo
endpoints. It builds on the shared
:class:`oauth2_provider.core.views.OAuthLibCoreMixin`.
"""

from django.http import HttpRequest
from oauthlib.oauth2.rfc6749 import errors as oauth2_errors

from oauth2_provider.authorization_server.response_modes import (
    add_params_to_authorization_redirect,
    response_mode_permitted,
)
from oauth2_provider.core.exceptions import FatalClientError
from oauth2_provider.core.utils import add_iss_to_redirect
from oauth2_provider.core.views import OAuthLibCoreMixin
from oauth2_provider.settings import oauth2_settings


class AuthorizationServerViewMixin(OAuthLibCoreMixin):
    """Authorization-server (and OpenID Connect Provider) view helpers.

    Wraps the oauthlib ``Server`` to produce authorization, token, revocation,
    device-authorization and userinfo responses, plus the authorization-error
    redirect helper.
    """

    def validate_authorization_request(self, request):
        """
        A wrapper method that calls validate_authorization_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.validate_authorization_request(request)

    def create_authorization_response(self, request, scopes, credentials, allow):
        """
        A wrapper method that calls create_authorization_response on `server_class`
        instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A space-separated string of provided scopes
        :param credentials: Authorization credentials dictionary containing
                           `client_id`, `state`, `redirect_uri` and `response_type`
        :param allow: True if the user authorize the client, otherwise False
        """
        # TODO: move this scopes conversion from and to string into a utils function
        scopes = scopes.split(" ") if scopes else []

        core = self.get_oauthlib_core()
        return core.create_authorization_response(request, scopes, credentials, allow)

    def create_device_authorization_response(self, request: HttpRequest):
        """
        A wrapper method that calls create_device_authorization_response on `server_class`
        instance.
        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.create_device_authorization_response(request)

    def create_token_response(self, request):
        """
        A wrapper method that calls create_token_response on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.create_token_response(request)

    def create_revocation_response(self, request):
        """
        A wrapper method that calls create_revocation_response on the
        `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.create_revocation_response(request)

    def create_userinfo_response(self, request):
        """
        A wrapper method that calls create_userinfo_response on the
        `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.create_userinfo_response(request)

    def error_response(self, error, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes awry.

        :param error: :attr:`OAuthToolkitError`
        """
        oauthlib_error = error.oauthlib_error

        # OpenID Connect Core 1.0 §3.1.2.6: if the Response Mode is not supported, the
        # error cannot be returned in it, so the request gets an HTTP 400 without Error
        # Response parameters. OAuth2Validator.validate_response_type refuses such a
        # mode during validation, but errors raised before oauthlib reaches it (a
        # missing or unknown response_type) or built by the toolkit (access_denied,
        # invalid_target) arrive here and must not be redirected either.
        response_mode = oauthlib_error.response_mode
        if (
            not isinstance(error, FatalClientError)
            and response_mode
            and not response_mode_permitted(oauthlib_error.response_type, response_mode)
        ):
            oauthlib_error = oauth2_errors.InvalidRequestFatalError(
                description="The requested response_mode is not supported for this response_type."
            )
            error = FatalClientError(error=oauthlib_error)

        # A fatal error means the client_id/redirect_uri combination could not be
        # trusted, so the error is rendered to the resource owner instead of
        # redirected (RFC 6749 §4.1.2.1: the server "MUST NOT automatically
        # redirect the user-agent to the invalid redirection URI").
        redirect = not isinstance(error, FatalClientError)

        redirect_uri = oauthlib_error.redirect_uri or ""
        # Implicit and hybrid errors go in the fragment, like their successful
        # responses (OpenID Connect Core 3.2.2.6 and 3.3.2.6).
        url = add_params_to_authorization_redirect(
            redirect_uri,
            oauthlib_error.urlencoded,
            oauthlib_error.response_type,
            oauthlib_error.response_mode,
        )

        # RFC 9207 §2 requires `iss` on every authorization response returned to
        # the client, including error responses. A fatal error returns nothing to
        # the client, so its context-only URL gets no `iss`.
        if redirect and redirect_uri and oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS:
            issuer = oauth2_settings.oauth2_authorization_server_issuer(self.request)
            url = add_iss_to_redirect(url, issuer)

        error_response = {
            "error": oauthlib_error,
            "url": url,
        }
        error_response.update(kwargs)

        return redirect, error_response
