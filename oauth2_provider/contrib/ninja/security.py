from typing import Any

from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import SuspiciousOperation
from django.http import HttpRequest
from ninja.security.http import HttpAuthBase

from ...core.backends_oauthlib import get_oauthlib_core
from ...models import AbstractAccessToken


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
        try:
            valid, r = oauthlib_core.verify_request(request, scopes=self.scopes)
        except ValueError as error:
            # `verify_request` parses the full request URI, so a malformed query string raises this
            # even when the token is supplied via header. Convert it to a 400, matching the behavior
            # of the DRF integration and `views.mixins`, rather than letting it surface as a 500.
            if str(error) == "Invalid hex encoding in query string.":
                raise SuspiciousOperation(error)
            raise

        if not valid:
            return None

        # Ninja only sets `request.auth`, not `request.user`: https://github.com/vitalik/django-ninja/issues/76
        # However, Django's AuthenticationMiddleware (which sets `request.user` from a session cookie)
        # is ubiquitous, so most code (including Ninja's own tutorials) assumes that `request.user` is
        # set to a User-like object.
        #
        # A token may have no user (e.g. with the `client_credentials` grant). In this case,
        # `request.user` will be an `AnonymousUser`, but the request will still be authenticated
        # by Ninja, with the token as `request.auth`.
        request.user = r.user if r.user is not None else AnonymousUser()

        return self.authenticate(request, r.access_token)

    def authenticate(self, request: HttpRequest, access_token: AbstractAccessToken) -> Any | None:
        """
        Determine whether authentication succeeds.

        If this returns a truthy value, authentication will succeed.
        Django Ninja will set the return value as `request.auth`.

        Subclasses may override this to implement additional authorization logic.
        """
        return access_token
