from typing import Any

from django.http import HttpRequest
from ninja.security.http import HttpAuthBase

from ...models import AbstractAccessToken
from ...oauth2_backends import get_oauthlib_core


# Don't inherit from `HttpBearer`, since we have our own header extraction logic
class HttpOAuth2(HttpAuthBase):
    """Perform OAuth2 authentication, for use with Django Ninja."""

    openapi_scheme: str = "bearer"

    def __init__(self, *, scopes: list[str] | None = None) -> None:
        super().__init__()
        # Copy list, since it's mutable
        self.scopes = list(scopes) if scopes is not None else []

    def __call__(self, request: HttpRequest) -> Any | None:
        oauthlib_core = get_oauthlib_core()
        valid, r = oauthlib_core.verify_request(request, scopes=self.scopes)

        if not valid:
            return None

        # Ninja doesn't automatically set `request.user`: https://github.com/vitalik/django-ninja/issues/76
        # However, Django's AuthenticationMiddleware (which does set this from a session cookie) is
        # ubiquitous, and even Ninja's own tutorials assume that `request.user` will somehow be set,
        # so ensure that authentication via OAuth2 doesn't violate expectations.
        request.user = r.user

        return self.authenticate(request, r.access_token)

    def authenticate(self, request: HttpRequest, access_token: AbstractAccessToken) -> Any | None:
        """
        Determine whether authentication succeeds.

        If this returns a truthy value, authentication will succeed.
        Django Ninja will set the return value as `request.auth`.

        Subclasses may override this to implement additional authorization logic.
        """
        return access_token
