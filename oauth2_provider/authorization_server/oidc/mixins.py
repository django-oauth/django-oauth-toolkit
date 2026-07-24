"""OpenID Connect Provider view-gating mixins.

These restrict OIDC-only endpoints (discovery, JWKS, userinfo, RP-Initiated
Logout) to deployments that have OIDC — and, for logout, RP-Initiated Logout —
enabled in settings.
"""

import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseNotFound

from oauth2_provider.settings import oauth2_settings


log = logging.getLogger("oauth2_provider")


class OIDCOnlyMixin:
    """
    Mixin for views that should only be accessible when OIDC is enabled.

    If OIDC is not enabled:

    * if DEBUG is True, raises an ImproperlyConfigured exception explaining why
    * otherwise, returns a 404 response, logging the same warning
    """

    debug_error_message = (
        "django-oauth-toolkit OIDC views are not enabled unless you "
        "have configured OIDC_ENABLED in the settings"
    )

    def dispatch(self, *args, **kwargs):
        if not oauth2_settings.OIDC_ENABLED:
            if settings.DEBUG:
                raise ImproperlyConfigured(self.debug_error_message)
            log.warning(self.debug_error_message)
            return HttpResponseNotFound()
        return super().dispatch(*args, **kwargs)


class OIDCLogoutOnlyMixin(OIDCOnlyMixin):
    """
    Mixin for views that should only be accessible when OIDC and OIDC RP-Initiated Logout are enabled.

    If either is not enabled:

    * if DEBUG is True, raises an ImproperlyConfigured exception explaining why
    * otherwise, returns a 404 response, logging the same warning
    """

    debug_error_message = (
        "The django-oauth-toolkit OIDC RP-Initiated Logout view is not enabled unless you "
        "have configured OIDC_RP_INITIATED_LOGOUT_ENABLED in the settings"
    )

    def dispatch(self, *args, **kwargs):
        if not oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED:
            if settings.DEBUG:
                raise ImproperlyConfigured(self.debug_error_message)
            log.warning(self.debug_error_message)
            return HttpResponseNotFound()
        return super().dispatch(*args, **kwargs)
