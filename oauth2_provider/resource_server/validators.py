"""Resource Server request-validation logic.

This module holds the Resource-Server slice of the OAuth2 request validator that
previously lived on :class:`oauth2_provider.oauth2_validators.OAuth2Validator`:

* the RFC 8707 resource-indicator matching functions, and
* :class:`ResourceServerValidatorMixin`, which provides bearer-token validation
  (RFC 7662 introspection client + local token lookup).

``OAuth2Validator`` composes the mixin, so the public class, its import path, and
its behavior are unchanged. Split out here so the resource-server concern lives
under the ``resource_server`` role package rather than inside the authorization
server's validator.
"""

import base64
import hashlib
import http.client
import logging
import posixpath
import urllib.parse
from collections import OrderedDict
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone

import requests
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware
from django.utils.translation import gettext_lazy as _

from oauth2_provider.core.utils import get_timezone
from oauth2_provider.models import get_access_token_model
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger("oauth2_provider")

AccessToken = get_access_token_model()


# Default ports used to normalize URIs before comparison, so that e.g.
# "https://api.example.com:443/foo" and "https://api.example.com/foo" match.
_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_and_validate_uri(uri):
    """Parse a URI and return (scheme, hostname, port, path) or None if invalid.

    Paths are normalized to resolve dot segments (RFC 3986 Section 5.2.4).
    For http and https URIs, an omitted port is normalized to the scheme default
    (RFC 3986 Section 6.2.3); for other schemes it remains None.
    URIs with userinfo or fragment components are rejected. A query component is
    accepted (RFC 8707 allows one on resource indicators) but is not part of the
    returned tuple, so it plays no role in matching.

    A non-string ``uri`` (e.g. a non-string element in a JSON ``resource`` array)
    returns None rather than raising, so callers fail closed with a clean
    ``invalid_target`` error instead of a TypeError / 500.
    """
    if not isinstance(uri, str):
        return None
    parsed = urllib.parse.urlsplit(uri)
    # "is not None" catches empty-but-present components ("https://@example.com",
    # "https://example.com/#") that truthiness checks would let through.
    if parsed.username is not None or parsed.password is not None:
        return None
    if parsed.fragment or "#" in uri:
        return None
    if not parsed.scheme or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    try:
        port = parsed.port
    except ValueError:
        # Non-numeric or out-of-range port
        return None
    if port is None:
        port = _SCHEME_DEFAULT_PORTS.get(scheme)
    path = posixpath.normpath(parsed.path or "/")
    return (scheme, parsed.hostname.lower(), port, path)


def is_valid_resource_uri(uri):
    """Return True if ``uri`` is acceptable as an RFC 8707 resource indicator.

    Accepted values are absolute URIs with a scheme and host, without userinfo
    or fragment components (e.g. ``https://api.example.com/path``).
    """
    return _parse_and_validate_uri(uri) is not None


def validate_resource_as_url_prefix(request_uri, audiences):
    """
    Default resource validator using URL prefix matching (RFC 8707).

    Validates that the request URI matches one of the token's audience claims
    using prefix matching. The audience URI acts as a base URI that the request
    must start with.

    URIs are parsed and compared component-by-component to prevent bypasses
    via userinfo injection or authority confusion.

    Examples:
        - Token audience: "https://api.example.com/foo"
        - Matches: "https://api.example.com/foo"
        - Matches: "https://api.example.com/foo/"
        - Matches: "https://api.example.com/foo/bar"
        - Rejects: "https://other.example.com/foo/bar"
        - Rejects: "https://api.example.com/bar"
        - Rejects: "https://api.example.com/food-blog"
        - Rejects: "https://api.example.com@evil.com/foo"

    Both ``request_uri`` and the audience values must be absolute URIs with a
    scheme and host; other absolute-URI forms (e.g. URNs) never match.

    :param request_uri: String URI of the current request (without query string)
    :param audiences: List of audience URI strings from token
    :return: True if token is valid for this request, False otherwise
    """
    if not audiences:
        return True

    request_parts = _parse_and_validate_uri(request_uri)
    if request_parts is None:
        return False

    req_scheme, req_host, req_port, req_path = request_parts
    req_path_normalized = req_path.rstrip("/") + "/"

    for audience in audiences:
        aud_parts = _parse_and_validate_uri(audience)
        if aud_parts is None:
            continue

        aud_scheme, aud_host, aud_port, aud_path = aud_parts
        if (req_scheme, req_host, req_port) != (aud_scheme, aud_host, aud_port):
            continue

        aud_path_normalized = aud_path.rstrip("/") + "/"
        if req_path_normalized.startswith(aud_path_normalized):
            return True

    return False


class ResourceServerValidatorMixin:
    """Resource-server bearer-token validation, composed into ``OAuth2Validator``.

    Provides the RFC 7662 introspection client and local access-token lookup used
    when this server acts as a resource server. Relies on a few helpers defined on
    the composed validator (``get_or_create_user_from_content``,
    ``_set_oauth2_error_on_request``), which resolve via ``self`` at runtime.
    """

    def _get_token_from_authentication_server(
        self, token, introspection_url, introspection_token, introspection_credentials
    ):
        """Use external introspection endpoint to "crack open" the token.
        :param introspection_url: introspection endpoint URL
        :param introspection_token: Bearer token
        :param introspection_credentials: Basic Auth credentials (id,secret)
        :return: :class:`models.AccessToken`

        Some RFC 7662 implementations (including this one) use a Bearer token while others use Basic
        Auth. Depending on the external AS's implementation, provide either the introspection_token
        or the introspection_credentials.

        If the resulting access_token identifies a username (e.g. Authorization Code grant), add
        that user to the UserModel. Also cache the access_token up until its expiry time or a
        configured maximum time.

        """
        headers = None
        if introspection_token:
            headers = {"Authorization": "Bearer {}".format(introspection_token)}
        elif introspection_credentials:
            client_id = introspection_credentials[0].encode("utf-8")
            client_secret = introspection_credentials[1].encode("utf-8")
            basic_auth = base64.b64encode(client_id + b":" + client_secret)
            headers = {"Authorization": "Basic {}".format(basic_auth.decode("utf-8"))}

        try:
            response = requests.post(introspection_url, data={"token": token}, headers=headers)
        except requests.exceptions.RequestException:
            log.exception("Introspection: Failed POST to %r in token lookup", introspection_url)
            return None

        # Log an exception when response from auth server is not successful
        if response.status_code != http.client.OK:
            log.exception(
                "Introspection: Failed to get a valid response "
                "from authentication server. Status code: {}, "
                "Reason: {}.".format(response.status_code, response.reason)
            )
            return None

        try:
            content = response.json()
        except ValueError:
            log.exception("Introspection: Failed to parse response as json")
            return None

        if "active" in content and content["active"] is True:
            if "username" in content:
                user = self.get_or_create_user_from_content(content)
            else:
                user = None

            max_caching_time = datetime.now(tz=datetime_timezone.utc) + timedelta(
                seconds=oauth2_settings.RESOURCE_SERVER_TOKEN_CACHING_SECONDS
            )

            if "exp" in content:
                expires = datetime.fromtimestamp(content["exp"], tz=datetime_timezone.utc)
                exp_time_zone = oauth2_settings.AUTHENTICATION_SERVER_EXP_TIME_ZONE
                if exp_time_zone != "UTC":
                    # Deprecated AUTHENTICATION_SERVER_EXP_TIME_ZONE workaround: reinterpret the
                    # exp wall-clock time as being in the configured (non-UTC) time zone.
                    expires = make_aware(expires.replace(tzinfo=None), timezone=get_timezone(exp_time_zone))
                if expires > max_caching_time:
                    expires = max_caching_time
            else:
                expires = max_caching_time

            scope = content.get("scope", "")

            if not settings.USE_TZ:
                expires = timezone.make_naive(expires, expires.tzinfo)

            # RFC 8707: Map introspection 'aud' claim to resource field.
            # RFC 7662 defines 'aud' as a string or array of strings. 'aud' is a
            # security restriction, so a malformed value must fail closed: treating
            # it as unrestricted would let the token through on any resource.
            aud = content.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            elif not isinstance(aud, list) or not all(isinstance(entry, str) for entry in aud):
                log.warning("Rejecting token: malformed 'aud' claim in introspection response: %r", aud)
                return None

            token_checksum = hashlib.sha256(token.encode("utf-8")).hexdigest()
            # Respect hashed-at-rest storage (RFC 9700): the resource-server token cache
            # is looked up by checksum, so it must not persist the cleartext token when
            # COMPLIANT_BCP_RFC9700_TOKEN_STORAGE is enabled.
            stored_token = "" if oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE else token
            access_token, _created = AccessToken.objects.update_or_create(
                token_checksum=token_checksum,
                defaults={
                    "token": stored_token,
                    "user": user,
                    "application": None,
                    "scope": scope,
                    "expires": expires,
                    "resource": aud,
                },
            )

            return access_token

    def validate_bearer_token(self, token, scopes, request):
        """
        When users try to access resources, check that provided token is valid
        """
        if not token:
            return False

        introspection_url = oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL
        introspection_token = oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN
        introspection_credentials = oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS

        access_token = self._load_access_token(token)

        # if there is no token or it's invalid then introspect the token if there's an external OAuth server
        if not access_token or not access_token.is_valid(scopes):
            if introspection_url and (introspection_token or introspection_credentials):
                access_token = self._get_token_from_authentication_server(
                    token, introspection_url, introspection_token, introspection_credentials
                )

        if access_token and access_token.is_valid(scopes):
            # RFC 8707: Only resource-restricted tokens are audience-checked, so
            # unrestricted tokens keep working with minimal request objects that
            # carry no uri. Restricted tokens fail closed when the uri is absent.
            if access_token.resource:
                # request.uri is the full URI from the oauthlib Request object
                request_uri = (getattr(request, "uri", None) or "").split("?")[0]
                if not access_token.allows_audience(request_uri):
                    request.oauth2_error = OrderedDict(
                        [
                            ("error", "invalid_token"),
                            (
                                "error_description",
                                _("The access token is not valid for this resource."),
                            ),
                        ]
                    )
                    return False

            request.client = access_token.application
            request.user = access_token.user
            request.scopes = list(access_token.scopes)

            # this is needed by django rest framework
            request.access_token = access_token
            return True
        else:
            self._set_oauth2_error_on_request(request, access_token, scopes)
            return False

    def _load_access_token(self, token):
        token_checksum = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return (
            AccessToken.objects.select_related("application", "user")
            .filter(token_checksum=token_checksum)
            .first()
        )
