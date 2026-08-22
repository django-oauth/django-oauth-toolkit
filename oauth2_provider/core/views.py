"""Shared view mixins.

``OAuthLibCoreMixin`` holds the oauthlib configuration and core-construction
machinery common to the authorization-server and resource-server view layers.
The role-specific behavior lives in
:class:`oauth2_provider.authorization_server.views.mixins.AuthorizationServerViewMixin`
(building authorization/token/revocation/userinfo responses) and
:class:`oauth2_provider.resource_server.mixins.ResourceServerViewMixin`
(verifying protected-resource requests).

``FormEncodedRequestMixin`` implements the ``REQUIRE_FORM_ENCODED_REQUEST_BODY``
gate for the endpoints whose request bodies the specifications define as
``application/x-www-form-urlencoded``.
"""

import logging
import warnings

from django.http import HttpRequest, HttpResponse, JsonResponse

from oauth2_provider.settings import oauth2_settings


log = logging.getLogger("oauth2_provider")

FORM_URLENCODED_MEDIA_TYPE = "application/x-www-form-urlencoded"


class FormEncodedRequestMixin:
    """
    Reject POST bodies that are not ``application/x-www-form-urlencoded``.

    The OAuth 2.0 endpoints this library serves take the parameters that make up the
    request in a form-encoded request body: the token endpoint
    (:rfc:`6749#section-4.1.3`, :rfc:`6749#section-4.3.2`, :rfc:`6749#section-4.4.2`
    and :rfc:`6749#section-6`), revocation (:rfc:`7009#section-2.1`), introspection
    (:rfc:`7662#section-2.1`), device authorization (:rfc:`8628#section-3.1`) and
    pushed authorization requests (:rfc:`9126#section-2.1`). Django only populates
    ``request.POST`` for form-encoded (and multipart) bodies, so a client that sends,
    say, JSON reaches the view with no parameters at all and gets a confusing error
    about a parameter it did supply -- a JSON token request is rejected as
    ``unsupported_grant_type``.

    Not applied to the OpenID Connect UserInfo endpoint: OpenID Connect Core
    section 5.3.1 allows a POST whose only credential is the ``Authorization`` header,
    and the form-encoding requirement of :rfc:`6750#section-2.2` is a condition on the
    client putting the access token *in the body*, not on the endpoint. Nor to Dynamic
    Client Registration, whose bodies :rfc:`7591` defines as ``application/json``.

    Enforcement is gated on ``REQUIRE_FORM_ENCODED_REQUEST_BODY`` because rejecting
    the bodies previously accepted (JSON via the deprecated ``JSONOAuthLibCore``
    backend, and multipart, which Django parses into ``request.POST`` but no
    specification permits here) is a breaking change for clients that rely on them.
    The ``False`` default is deprecated and scheduled to become ``True`` in 4.0: while
    it is off a non-compliant body is still passed through, but each one emits a
    ``DeprecationWarning`` (and a log line) naming the client-visible change to come.
    Nothing is emitted for a compliant request, so a deployment whose clients already
    send form-encoded bodies stays quiet -- and for it the coming default flip is a
    no-op.

    Only requests carrying a body are checked: the endpoints that also answer ``GET``
    (introspection) take their parameters from the query string there, where no media
    type applies.

    Subclasses set :attr:`form_encoded_endpoint` to the endpoint description named in
    the error, which is also where the spec citation lives.
    """

    #: Description of the endpoint, with the citation defining it, used in the error.
    form_encoded_endpoint = "The OAuth 2.0 token endpoint (RFC 6749 section 3.2)"

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        response = self.form_encoded_body_error(request)
        if response is not None:
            return response
        return super().dispatch(request, *args, **kwargs)

    def form_encoded_body_error(self, request: HttpRequest) -> JsonResponse | None:
        """
        Return a ``415 Unsupported Media Type`` response for a request whose body is not
        form-encoded, or ``None`` when the request may proceed.

        While ``REQUIRE_FORM_ENCODED_REQUEST_BODY`` is ``False`` a non-compliant body
        proceeds, but warns that it will not once the default flips in 4.0.
        """
        if request.method != "POST":
            return None
        # ``HttpRequest.content_type`` is the media type alone, lower-cased and with
        # any parameters stripped, so "Application/X-WWW-Form-Urlencoded; charset=UTF-8"
        # compares equal here. A request with no Content-Type header gives "".
        if request.content_type == FORM_URLENCODED_MEDIA_TYPE:
            return None

        received = request.content_type or "no Content-Type header"
        detail = (
            f"{self.form_encoded_endpoint} takes its parameters in an "
            f"{FORM_URLENCODED_MEDIA_TYPE} request body; got {received}."
        )
        if not oauth2_settings.REQUIRE_FORM_ENCODED_REQUEST_BODY:
            # Warn only on the non-compliant path, so a deployment whose clients already
            # comply never sees this. Mirrors the RFC 9700 request-time gates in
            # :mod:`oauth2_provider.core.bcp`, which is RFC 9700-specific and so not
            # reused here.
            message = (
                f"{detail} The request is currently allowed to proceed because "
                'OAUTH2_PROVIDER["REQUIRE_FORM_ENCODED_REQUEST_BODY"] is False; this '
                "default is scheduled to change to True in django-oauth-toolkit 4.0, "
                "after which such a request is rejected with HTTP 415. Set "
                'OAUTH2_PROVIDER["REQUIRE_FORM_ENCODED_REQUEST_BODY"] to True to adopt '
                "the compliant behavior now."
            )
            warnings.warn(message, DeprecationWarning, stacklevel=2)
            log.warning(message)
            return None

        return JsonResponse({"error": "invalid_request", "error_description": detail}, status=415)


class OAuthLibCoreMixin:
    """
    Shared configuration for the oauthlib-backed views.

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

    def get_scopes(self):
        """
        This should return the list of scopes required to access the resources.
        By default it returns an empty list.
        """
        return []
