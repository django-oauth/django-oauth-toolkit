"""Authorization-server view mixin.

``AuthorizationServerViewMixin`` provides the oauthlib response-building helpers
used by the authorization, token, revocation, device-authorization and userinfo
endpoints. It builds on the shared
:class:`oauth2_provider.core.views.OAuthLibCoreMixin`.
"""

from django.http import HttpRequest

from oauth2_provider.core.backends_oauthlib import _add_iss_to_redirect
from oauth2_provider.core.exceptions import FatalClientError
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

        redirect_uri = oauthlib_error.redirect_uri or ""
        separator = "&" if "?" in redirect_uri else "?"

        url = redirect_uri + separator + oauthlib_error.urlencoded

        # RFC 9207 §2 requires `iss` on *every* authorization response, including error
        # responses -- not just successful ones (see _add_iss_to_redirect's other call
        # site in backends_oauthlib.create_authorization_response). Only add it when
        # there's an actual redirect_uri to redirect to: a FatalClientError has none (it
        # renders an error page instead of redirecting, since the redirect_uri itself
        # couldn't be trusted), and there's nothing to add `iss` to in that case.
        if redirect_uri and oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS:
            issuer = oauth2_settings.oauth2_authorization_server_issuer(self.request)
            url = _add_iss_to_redirect(url, issuer)

        error_response = {
            "error": oauthlib_error,
            "url": url,
        }
        error_response.update(kwargs)

        # If we got a malicious redirect_uri or client_id, we will *not* redirect back to the URL.
        if isinstance(error, FatalClientError):
            redirect = False
        else:
            redirect = True

        return redirect, error_response
