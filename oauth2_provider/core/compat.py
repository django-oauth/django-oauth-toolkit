"""
The `compat` module provides support for backwards compatibility with older
versions of Django, Python and oauthlib.
"""

from oauthlib.oauth2.rfc8628.grant_types import DeviceCodeGrant


try:
    # Django 5.1 introduced LoginRequiredMiddleware, and login_not_required decorator
    from django.contrib.auth.decorators import login_not_required
except ImportError:

    def login_not_required(view_func):
        return view_func


# oauthlib 4.0.1 made the device code grant validate RFC 8628 requests itself: the
# device authorization request's scope (returning the resolved scope with the
# response) and, at the token request, the device code's status through the
# ``RequestValidator.validate_device_code`` hook, bound to the authenticated client.
# Older oauthlib left both to the caller.
OAUTHLIB_VALIDATES_DEVICE_CODE = hasattr(DeviceCodeGrant, "validate_device_code")

__all__ = ["OAUTHLIB_VALIDATES_DEVICE_CODE", "login_not_required"]
