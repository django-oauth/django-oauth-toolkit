import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.http import HttpRequest, HttpResponseForbidden, HttpResponseNotFound

from ..exceptions import FatalClientError
from ..scopes import get_scopes_backend
from ..settings import oauth2_settings


log = logging.getLogger("oauth2_provider")

SAFE_HTTP_METHODS = ["GET", "HEAD", "OPTIONS"]


class OAuthLibMixin:
    """
    This mixin decouples Django OAuth Toolkit from OAuthLib.

    Users can configure the Server, Validator and OAuthlibCore
    classes used by this mixin by setting the following class
    variables:

      * server_class
      * validator_class
      * oauthlib_backend_class

    If these class variables are not set, it will fall back to using the classes
    specified in oauth2_settings (OAUTH2_SERVER_CLASS, OAUTH2_VALIDATOR_CLASS
    and OAUTH2_BACKEND_CLASS).
    """

    server_class = None
    validator_class = None
    oauthlib_backend_class = None

    @classmethod
    def get_server_class(cls):
        """
        Return the OAuthlib server class to use
        """
        if cls.server_class is None:
            return oauth2_settings.OAUTH2_SERVER_CLASS
        else:
            return cls.server_class

    @classmethod
    def get_validator_class(cls):
        """
        Return the RequestValidator implementation class to use
        """
        if cls.validator_class is None:
            return oauth2_settings.OAUTH2_VALIDATOR_CLASS
        else:
            return cls.validator_class

    @classmethod
    def get_oauthlib_backend_class(cls):
        """
        Return the OAuthLibCore implementation class to use
        """
        if cls.oauthlib_backend_class is None:
            return oauth2_settings.OAUTH2_BACKEND_CLASS
        else:
            return cls.oauthlib_backend_class

    @classmethod
    def get_server(cls):
        """
        Return an instance of `server_class` initialized with a `validator_class`
        object
        """
        server_class = cls.get_server_class()
        validator_class = cls.get_validator_class()
        server_kwargs = oauth2_settings.server_kwargs
        return server_class(validator_class(), **server_kwargs)

    @classmethod
    def get_oauthlib_core(cls):
        """
        Cache and return `OAuthlibCore` instance so it will be created only on first request
        unless ALWAYS_RELOAD_OAUTHLIB_CORE is True.
        """
        if not hasattr(cls, "_oauthlib_core") or oauth2_settings.ALWAYS_RELOAD_OAUTHLIB_CORE:
            server = cls.get_server()
            core_class = cls.get_oauthlib_backend_class()
            cls._oauthlib_core = core_class(server)
        return cls._oauthlib_core

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

    def verify_request(self, request):
        """
        A wrapper method that calls verify_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()

        try:
            return core.verify_request(request, scopes=self.get_scopes())
        except ValueError as error:
            if str(error) == "Invalid hex encoding in query string.":
                raise SuspiciousOperation(error)
            else:
                raise

    def get_scopes(self):
        """
        This should return the list of scopes required to access the resources.
        By default it returns an empty list.
        """
        return []

    def error_response(self, error, **kwargs):
        """
        Return an error to be displayed to the resource owner if anything goes awry.

        :param error: :attr:`OAuthToolkitError`
        """
        oauthlib_error = error.oauthlib_error

        redirect_uri = oauthlib_error.redirect_uri or ""
        separator = "&" if "?" in redirect_uri else "?"

        error_response = {
            "error": oauthlib_error,
            "url": redirect_uri + separator + oauthlib_error.urlencoded,
        }
        error_response.update(kwargs)

        # If we got a malicious redirect_uri or client_id, we will *not* redirect back to the URL.
        if isinstance(error, FatalClientError):
            redirect = False
        else:
            redirect = True

        return redirect, error_response

    def authenticate_client(self, request):
        """Returns a boolean representing if client is authenticated with client credentials
        method. Returns `True` if authenticated.

        :param request: The current django.http.HttpRequest object
        """
        core = self.get_oauthlib_core()
        return core.authenticate_client(request)


class ScopedResourceMixin:
    """
    Helper mixin that implements "scopes handling" behaviour
    """

    required_scopes = None

    def get_scopes(self, *args, **kwargs):
        """
        Return the scopes needed to access the resource

        :param args: Support scopes injections from the outside (not yet implemented)
        """
        if self.required_scopes is None:
            raise ImproperlyConfigured(
                "ProtectedResourceMixin requires either a definition of 'required_scopes'"
                " or an implementation of 'get_scopes()'"
            )
        else:
            return self.required_scopes


class ProtectedResourceMixin(OAuthLibMixin):
    """
    Helper mixin that implements OAuth2 protection on request dispatch,
    specially useful for Django Generic Views
    """

    def dispatch(self, request, *args, **kwargs):
        # let preflight OPTIONS requests pass
        if request.method.upper() == "OPTIONS":
            return super().dispatch(request, *args, **kwargs)

        # check if the request is valid and the protected resource may be accessed
        valid, r = self.verify_request(request)
        if valid:
            request.resource_owner = r.user
            return super().dispatch(request, *args, **kwargs)
        else:
            return HttpResponseForbidden()


class ReadWriteScopedResourceMixin(ScopedResourceMixin, OAuthLibMixin):
    """
    Helper mixin that implements "read and write scopes" behavior
    """

    required_scopes = []
    read_write_scope = None

    def __new__(cls, *args, **kwargs):
        provided_scopes = get_scopes_backend().get_all_scopes()
        read_write_scopes = [oauth2_settings.READ_SCOPE, oauth2_settings.WRITE_SCOPE]

        if not set(read_write_scopes).issubset(set(provided_scopes)):
            raise ImproperlyConfigured(
                "ReadWriteScopedResourceMixin requires following scopes {}"
                ' to be in OAUTH2_PROVIDER["SCOPES"] list in settings'.format(read_write_scopes)
            )

        return super().__new__(cls, *args, **kwargs)

    def dispatch(self, request, *args, **kwargs):
        if request.method.upper() in SAFE_HTTP_METHODS:
            self.read_write_scope = oauth2_settings.READ_SCOPE
        else:
            self.read_write_scope = oauth2_settings.WRITE_SCOPE

        return super().dispatch(request, *args, **kwargs)

    def get_scopes(self, *args, **kwargs):
        scopes = super().get_scopes(*args, **kwargs)

        # this returns a copy so that self.required_scopes is not modified
        return scopes + [self.read_write_scope]


class ClientProtectedResourceMixin(OAuthLibMixin):
    """Mixin for protecting resources with client authentication as mentioned in rfc:`3.2.1`
    This involves authenticating with any of: HTTP Basic Auth, Client Credentials and
    Access token in that order. Breaks off after first validation.
    """

    def dispatch(self, request, *args, **kwargs):
        # let preflight OPTIONS requests pass
        if request.method.upper() == "OPTIONS":
            return super().dispatch(request, *args, **kwargs)
        # Validate either with HTTP basic or client creds in request body.
        # TODO: Restrict to POST.
        valid = self.authenticate_client(request)
        if not valid:
            # Alternatively allow access tokens
            # check if the request is valid and the protected resource may be accessed
            valid, r = self.verify_request(request)
            if valid:
                request.resource_owner = r.user
                return super().dispatch(request, *args, **kwargs)
            return HttpResponseForbidden()
        else:
            return super().dispatch(request, *args, **kwargs)


class OIDCOnlyMixin:
    """
    Mixin for views that should only be accessible when OIDC is enabled.

    If OIDC is not enabled:

    * if DEBUG is True, raises an ImproperlyConfigured exception explaining why
    * otherwise, returns a 404 response, logging the same warning
    """

    debug_error_message = (
        "django-oauth-toolkit OIDC views are not enabled unless you "
        "have configured OIDC_ENABLED in the settings"
    )

    def dispatch(self, *args, **kwargs):
        if not oauth2_settings.OIDC_ENABLED:
            if settings.DEBUG:
                raise ImproperlyConfigured(self.debug_error_message)
            log.warning(self.debug_error_message)
            return HttpResponseNotFound()
        return super().dispatch(*args, **kwargs)


class OIDCLogoutOnlyMixin(OIDCOnlyMixin):
    """
    Mixin for views that should only be accessible when OIDC and OIDC RP-Initiated Logout are enabled.

    If either is not enabled:

    * if DEBUG is True, raises an ImproperlyConfigured exception explaining why
    * otherwise, returns a 404 response, logging the same warning
    """

    debug_error_message = (
        "The django-oauth-toolkit OIDC RP-Initiated Logout view is not enabled unless you "
        "have configured OIDC_RP_INITIATED_LOGOUT_ENABLED in the settings"
    )

    def dispatch(self, *args, **kwargs):
        if not oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED:
            if settings.DEBUG:
                raise ImproperlyConfigured(self.debug_error_message)
            log.warning(self.debug_error_message)
            return HttpResponseNotFound()
        return super().dispatch(*args, **kwargs)
