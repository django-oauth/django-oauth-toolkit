from collections import OrderedDict

from django.core.exceptions import SuspiciousOperation
from rest_framework.authentication import BaseAuthentication

from ...oauth2_backends import get_oauthlib_core
from ...settings import oauth2_settings


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
    """

    def authenticate_header(self, request):
        header = super().authenticate_header(request)
        metadata_url = oauth2_settings.oauth2_resource_metadata_url(request)
        if metadata_url:
            header = '{header},resource_metadata="{url}"'.format(header=header, url=metadata_url)
        return header
