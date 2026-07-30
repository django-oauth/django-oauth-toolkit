class OAuthToolkitError(Exception):
    """
    Base class for exceptions
    """

    def __init__(self, error=None, redirect_uri=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.oauthlib_error = error

        if redirect_uri:
            self.oauthlib_error.redirect_uri = redirect_uri


class FatalClientError(OAuthToolkitError):
    """
    Class for critical errors
    """

    pass


class OIDCError(Exception):
    """
    General class to derive from for all OIDC related errors.
    """

    status_code = 400
    error = None

    def __init__(self, description=None):
        if description is not None:
            self.description = description

        message = "({}) {}".format(self.error, self.description)
        super().__init__(message)


class InvalidRequestFatalError(OIDCError):
    """
    For fatal errors. These are requests with invalid parameter values, missing parameters or otherwise
    incorrect requests.
    """

    error = "invalid_request"


class ClientIdMissmatch(InvalidRequestFatalError):
    description = "Mismatch between the Client ID of the ID Token and the Client ID that was provided."


class InvalidOIDCClientError(InvalidRequestFatalError):
    description = "The client is unknown or no client has been included."


class InvalidOIDCRedirectURIError(InvalidRequestFatalError):
    description = "Invalid post logout redirect URI."


class InvalidIDTokenError(InvalidRequestFatalError):
    description = "The ID Token is expired, revoked, malformed, or otherwise invalid."


class LogoutDenied(OIDCError):
    error = "logout_denied"
    description = "Logout has been refused by the user."
