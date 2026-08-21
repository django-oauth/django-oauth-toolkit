"""Shared view mixin.

``OAuthLibCoreMixin`` holds the oauthlib configuration and core-construction
machinery common to the authorization-server and resource-server view layers.
The role-specific behavior lives in
:class:`oauth2_provider.authorization_server.views.mixins.AuthorizationServerViewMixin`
(building authorization/token/revocation/userinfo responses) and
:class:`oauth2_provider.resource_server.mixins.ResourceServerViewMixin`
(verifying protected-resource requests).
"""

from oauth2_provider.settings import oauth2_settings


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
