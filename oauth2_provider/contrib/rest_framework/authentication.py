from collections import OrderedDict

from django.core.exceptions import SuspiciousOperation
from rest_framework.authentication import BaseAuthentication

from ...core.backends_oauthlib import get_oauthlib_core
from ...resource_server.www_authenticate import build_bearer_challenge


class OAuth2Authentication(BaseAuthentication):
    """
    OAuth 2 authentication backend using `django-oauth-toolkit`
    """

    www_authenticate_realm = "api"

    def _dict_to_string(self, my_dict):
        """
        Return a string of comma-separated key-value pairs (e.g. k="v",k2="v2").
        """
        return ",".join(['{k}="{v}"'.format(k=k, v=v) for k, v in my_dict.items()])

    def authenticate(self, request):
        """
        Returns two-tuple of (user, token) if authentication succeeds,
        or None otherwise.
        """
        if request is None:
            return None
        oauthlib_core = get_oauthlib_core()
        try:
            valid, r = oauthlib_core.verify_request(request, scopes=[])
        except ValueError as error:
            if str(error) == "Invalid hex encoding in query string.":
                raise SuspiciousOperation(error)
            raise
        else:
            if valid:
                return r.user, r.access_token
        request.oauth2_error = getattr(r, "oauth2_error", {})
        return None

    def authenticate_header(self, request):
        """
        Bearer is the only finalized type currently
        """
        www_authenticate_attributes = OrderedDict(
            [
                ("realm", self.www_authenticate_realm),
            ]
        )
        oauth2_error = getattr(request, "oauth2_error", {})
        www_authenticate_attributes.update(oauth2_error)
        return "Bearer {attributes}".format(
            attributes=self._dict_to_string(www_authenticate_attributes),
        )


class OAuth2ProtectedResourceAuthentication(OAuth2Authentication):
    """
    RFC 9728 variant of :class:`OAuth2Authentication`.

    Adds a ``resource_metadata`` parameter to the ``WWW-Authenticate`` challenge,
    pointing clients at this server's protected-resource metadata document
    (``/.well-known/oauth-protected-resource``). Opt in by listing this class in a
    view's ``authentication_classes``; the base ``OAuth2Authentication`` challenge is
    left unchanged.

    Set ``resource_metadata_url`` (or override :meth:`get_resource_metadata_url`) to
    advertise a specific metadata document — e.g. the RFC 9728 path-component form
    for a path-based/multi-tenant resource — instead of the root route.
    """

    resource_metadata_url = None

    def get_resource_metadata_url(self, request):
        """URL advertised in ``resource_metadata`` (``None`` uses the root route)."""
        return self.resource_metadata_url

    def authenticate_header(self, request):
        # Delegate to the shared builder so every Bearer challenge is rendered
        # consistently and with proper quoted-string escaping. It appends
        # ``resource_metadata`` only when a URL is available.
        oauth2_error = getattr(request, "oauth2_error", {})
        url = self.get_resource_metadata_url(request)
        extra = {} if url is None else {"resource_metadata_url": url}
        return build_bearer_challenge(
            request, oauth2_error=oauth2_error, realm=self.www_authenticate_realm, **extra
        )
