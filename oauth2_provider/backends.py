from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation

from .oauth2_backends import get_oauthlib_core


UserModel = get_user_model()
OAuthLibCore = get_oauthlib_core()


class OAuth2Backend:
    """
    Authenticate against an OAuth2 access token
    """

    def authenticate(self, request=None, **credentials):
        if request is not None:
            try:
                valid, request = OAuthLibCore.verify_request(request, scopes=[])
            except ValueError as error:
                if str(error) == "Invalid hex encoding in query string.":
                    raise SuspiciousOperation(error)
                else:
                    raise
            else:
                if valid:
                    return request.user

        return None

    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
