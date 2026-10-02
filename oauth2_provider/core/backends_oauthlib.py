import json
import warnings
from urllib.parse import urlparse, urlunparse

from django.http import HttpRequest
from oauthlib import oauth2
from oauthlib.common import Request as OauthlibRequest
from oauthlib.common import quote, urlencode, urlencoded
from oauthlib.oauth2 import OAuth2Error

from oauth2_provider.core.bcp import bcp_compliant
from oauth2_provider.core.exceptions import FatalClientError, OAuthToolkitError
from oauth2_provider.core.utils import add_iss_to_redirect
from oauth2_provider.settings import oauth2_settings


#: Name of the attribute :meth:`OAuthLibCore.authenticate_client_request` sets on the
#: Django ``HttpRequest`` to record the client it authenticated: the application when
#: authentication succeeded, ``None`` otherwise. The token introspection endpoint reads
#: it to authorize the client (RFC 7662 section 4). Private: a backend reports the client
#: by calling ``authenticate_client_request()``, never by setting this attribute itself.
_AUTHENTICATED_CLIENT_ATTRIBUTE = "_oauth2_provider_authenticated_client"


class OAuthLibCore:
    """
    Wrapper for oauth Server providing django-specific interfaces.

    Meant for things like extracting request data and converting
    everything to formats more palatable for oauthlib's Server.
    """

    def __init__(self, server=None):
        """
        :params server: An instance of oauthlib.oauth2.Server class
        """
        validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
        validator = validator_class()
        server_kwargs = oauth2_settings.server_kwargs
        self.server = server or oauth2_settings.OAUTH2_SERVER_CLASS(validator, **server_kwargs)

    def _get_escaped_full_path(self, request):
        """
        Django considers "safe" some characters that aren't so for oauthlib.
        We have to search for them and properly escape.
        """
        parsed = list(urlparse(request.get_full_path()))
        unsafe = set(c for c in parsed[4]).difference(urlencoded)
        for c in unsafe:
            parsed[4] = parsed[4].replace(c, quote(c, safe=b""))

        return urlunparse(parsed)

    def _get_extra_credentials(self, request):
        """
        Produce extra credentials for token response. This dictionary will be
        merged with the response.
        See also: `oauthlib.oauth2.rfc6749.TokenEndpoint.create_token_response`

        :param request: The current django.http.HttpRequest object
        :return: dictionary of extra credentials or None (default)
        """
        return None

    def _extract_params(self, request):
        """
        Extract parameters from the Django request object.
        Such parameters will then be passed to OAuthLib to build its own
        Request object. The body should be encoded using OAuthLib urlencoded.
        """
        uri = self._get_escaped_full_path(request)
        http_method = request.method
        headers = self.extract_headers(request)
        body = urlencode(self.extract_body(request))
        return uri, http_method, body, headers

    def extract_headers(self, request):
        """
        Extracts headers from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: a dictionary with OAuthLib needed headers
        """
        headers = request.META.copy()
        if "wsgi.input" in headers:
            del headers["wsgi.input"]
        if "wsgi.errors" in headers:
            del headers["wsgi.errors"]
        if "HTTP_AUTHORIZATION" in headers:
            headers["Authorization"] = headers["HTTP_AUTHORIZATION"]
        if "CONTENT_TYPE" in headers:
            headers["Content-Type"] = headers["CONTENT_TYPE"]
        # Add Access-Control-Allow-Origin header to the token endpoint response for authentication code grant,
        # if the origin is allowed by RequestValidator.is_origin_allowed.
        # https://github.com/oauthlib/oauthlib/pull/791
        if "HTTP_ORIGIN" in headers:
            headers["Origin"] = headers["HTTP_ORIGIN"]
        if request.is_secure():
            headers["X_DJANGO_OAUTH_TOOLKIT_SECURE"] = "1"
        elif "X_DJANGO_OAUTH_TOOLKIT_SECURE" in headers:
            del headers["X_DJANGO_OAUTH_TOOLKIT_SECURE"]

        return headers

    def extract_body(self, request):
        """
        Extracts the POST body from the Django request object

        Repeated ``resource`` parameters are preserved because RFC 8707 allows
        clients to request multiple resources by repeating the parameter. All
        other repeated parameters keep Django's last-value-wins behavior.

        :param request: The current django.http.HttpRequest object
        :return: provided POST parameters as key/value pairs
        """
        return [
            (key, value)
            for key, values in request.POST.lists()
            for value in (values if key == "resource" else values[-1:])
        ]

    def validate_authorization_request(self, request):
        """
        A wrapper method that calls validate_authorization_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        try:
            uri, http_method, body, headers = self._extract_params(request)
            scopes, credentials = self.server.validate_authorization_request(
                uri, http_method=http_method, body=body, headers=headers
            )

            return scopes, credentials
        except oauth2.FatalClientError as error:
            raise FatalClientError(error=error)
        except oauth2.OAuth2Error as error:
            raise OAuthToolkitError(error=error)

    def create_authorization_response(self, request, scopes, credentials, allow):
        """
        A wrapper method that calls create_authorization_response on `server_class`
        instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A list of provided scopes
        :param credentials: Authorization credentials dictionary containing
                           `client_id`, `state`, `redirect_uri`, `response_type`
        :param allow: True if the user authorize the client, otherwise False
        """
        try:
            if not allow:
                raise oauth2.AccessDeniedError(state=credentials.get("state", None))

            # add current user to credentials. this will be used by OAUTH2_VALIDATOR_CLASS
            credentials["user"] = request.user
            request_uri, http_method, _, request_headers = self._extract_params(request)

            headers, body, status = self.server.create_authorization_response(
                uri=request_uri,
                http_method=http_method,
                headers=request_headers,
                scopes=scopes,
                credentials=credentials,
            )
            uri = headers.get("Location", None)

            # RFC 9207 / RFC 9700 §4.4: include the `iss` authorization-response
            # parameter so clients can detect mix-up attacks. Gated by
            # COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS. Omission is an ambient config
            # posture (it would apply to every authorization response), so it is surfaced
            # by the `--deploy` system check W005 rather than a per-response warning.
            if uri is not None and oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS:
                issuer = oauth2_settings.oauth2_authorization_server_issuer(request)
                uri = add_iss_to_redirect(uri, issuer)
                headers["Location"] = uri

            return uri, headers, body, status

        except oauth2.FatalClientError as error:
            raise FatalClientError(error=error, redirect_uri=credentials["redirect_uri"])
        except oauth2.OAuth2Error as error:
            raise OAuthToolkitError(error=error, redirect_uri=credentials["redirect_uri"])

    def create_device_authorization_response(self, request: HttpRequest):
        uri, http_method, body, headers = self._extract_params(request)
        try:
            headers, body, status = self.server.create_device_authorization_response(
                uri, http_method, body, headers
            )
            return headers, body, status
        except OAuth2Error as exc:
            return exc.headers, exc.json, exc.status_code

    def create_token_response(self, request):
        """
        A wrapper method that calls create_token_response on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)
        extra_credentials = self._get_extra_credentials(request)

        try:
            headers, body, status = self.server.create_token_response(
                uri, http_method, body, headers, extra_credentials
            )
            uri = headers.get("Location", None)
            return uri, headers, body, status
        except OAuth2Error as exc:
            return None, exc.headers, exc.json, exc.status_code

    def create_revocation_response(self, request):
        """
        A wrapper method that calls create_revocation_response on a
        `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)

        headers, body, status = self.server.create_revocation_response(uri, http_method, body, headers)
        uri = headers.get("Location", None)

        return uri, headers, body, status

    def create_userinfo_response(self, request):
        """
        A wrapper method that calls create_userinfo_response on a
        `server_class` instance.

        :param request: The current django.http.HttpRequest object
        """
        uri, http_method, body, headers = self._extract_params(request)
        try:
            headers, body, status = self.server.create_userinfo_response(uri, http_method, body, headers)
            uri = headers.get("Location", None)
            return uri, headers, body, status
        except OAuth2Error as exc:
            return None, exc.headers, exc.json, exc.status_code

    def verify_request(self, request, scopes):
        """
        A wrapper method that calls verify_request on `server_class` instance.

        :param request: The current django.http.HttpRequest object
        :param scopes: A list of scopes required to verify so that request is verified
        """
        uri, http_method, body, headers = self._extract_params(request)

        # RFC 9700 §4.3.2 / RFC 6750 §5.3: access tokens MUST NOT be transmitted in
        # the URI query string. Gated by COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT.
        if "access_token" in request.GET and bcp_compliant(
            "COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT",
            "Presenting an OAuth 2.0 access token in the URI query string",
        ):
            return False, None

        # RFC 8707: audience validation compares the token's resource indicators
        # against the request URI, so the URI must be absolute. build_absolute_uri
        # honors SECURE_PROXY_SSL_HEADER / USE_X_FORWARDED_HOST when deployed
        # behind a TLS-terminating proxy.
        uri = request.build_absolute_uri(uri)

        valid, r = self.server.verify_request(uri, http_method, body, headers, scopes=scopes)
        return valid, r

    def authenticate_client(self, request: HttpRequest) -> bool:
        """Wrapper to call  `authenticate_client` on `server_class` instance.

        Delegates to :meth:`authenticate_client_request`, so it records the
        authenticated client on *request* as well.

        :param request: The current django.http.HttpRequest object
        """
        valid, _oauthlib_request = self.authenticate_client_request(request)
        return valid

    def authenticate_client_request(self, request: HttpRequest) -> tuple[bool, OauthlibRequest]:
        """Authenticate the client of *request* and return the oauthlib request too.

        Like :meth:`authenticate_client`, but also returns the oauthlib request the
        validator worked on, so the caller can inspect the authenticated client
        (``oauthlib_request.client``) -- e.g. to authorize it for an endpoint. The
        ``client`` attribute is only meaningful when the returned flag is ``True``.

        It also records the outcome on *request*, under
        :data:`_AUTHENTICATED_CLIENT_ATTRIBUTE`: the authenticated client when the
        validator accepted it, ``None`` otherwise.

        :param request: The current django.http.HttpRequest object
        :return: ``(valid, oauthlib_request)``
        """
        uri, http_method, body, headers = self._extract_params(request)
        oauth_request = OauthlibRequest(uri, http_method, body, headers)
        valid = self.server.request_validator.authenticate_client(oauth_request)
        client = getattr(oauth_request, "client", None) if valid else None
        setattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE, client)
        return valid, oauth_request


class JSONOAuthLibCore(OAuthLibCore):
    """
    Extends the default OAuthLibCore to parse ``application/json`` request bodies.

    .. deprecated:: 3.4.1
        The OAuth token, introspection, and revocation endpoints are
        defined to use ``application/x-www-form-urlencoded`` request bodies
        (RFC 6749, RFC 7662, RFC 7009). Reading ``application/json`` on these
        endpoints is non-standard and breaks interoperability with spec-compliant
        clients. Scheduled for removal in 4.0 (see #1773).
    """

    def __init__(self, server=None):
        warnings.warn(
            "JSONOAuthLibCore (OAUTH2_PROVIDER['OAUTH2_BACKEND_CLASS'] = "
            "'oauth2_provider.core.backends_oauthlib.JSONOAuthLibCore') is deprecated and will be "
            "removed in django-oauth-toolkit 4.0. The OAuth token, "
            "introspection, and revocation endpoints are defined to use "
            "application/x-www-form-urlencoded request bodies (RFC 6749, RFC 7662, RFC 7009); "
            "reading application/json on them is non-standard and breaks interoperability "
            "with spec-compliant clients. To migrate, remove the "
            "OAUTH2_PROVIDER['OAUTH2_BACKEND_CLASS'] override (the default "
            "'oauth2_provider.core.backends_oauthlib.OAuthLibCore' reads form-encoded bodies) and "
            "have clients send application/x-www-form-urlencoded request bodies.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(server)

    def extract_body(self, request):
        """
        Extracts the JSON body from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: provided POST parameters "urlencodable"
        """
        try:
            body = json.loads(request.body.decode("utf-8")).items()
        except AttributeError:
            body = ""
        except ValueError:
            body = ""

        return body


def get_oauthlib_core():
    """
    Utility function that returns an instance of the configured
    ``OAUTH2_BACKEND_CLASS`` (by default
    :class:`oauth2_provider.core.backends_oauthlib.OAuthLibCore`).
    """
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    validator = validator_class()
    server_kwargs = oauth2_settings.server_kwargs
    server = oauth2_settings.OAUTH2_SERVER_CLASS(validator, **server_kwargs)
    return oauth2_settings.OAUTH2_BACKEND_CLASS(server)


def __getattr__(name):
    # `_add_iss_to_redirect` moved to `oauth2_provider.core.utils.add_iss_to_redirect`
    # (public). Serve the old private name dynamically so existing imports keep
    # working while warning, without shadowing the canonical helper.
    if name == "_add_iss_to_redirect":
        warnings.warn(
            "oauth2_provider.core.backends_oauthlib._add_iss_to_redirect has moved to "
            "oauth2_provider.core.utils.add_iss_to_redirect. The old private name is "
            "deprecated and will be removed in django-oauth-toolkit 4.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return add_iss_to_redirect
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
