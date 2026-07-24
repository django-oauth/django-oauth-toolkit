"""
Permission classes for the Dynamic Client Registration endpoint (RFC 7591).

Each class must implement ``has_permission(request) -> bool``.
Configure via ``OAUTH2_PROVIDER["DCR_REGISTRATION_PERMISSION_CLASSES"]``.
"""

from django.middleware.csrf import CsrfViewMiddleware

from oauth2_provider.core.utils import parse_bearer_token


class _CsrfCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        # Return the failure reason instead of an HttpResponseForbidden
        return reason


def enforce_csrf(request):
    """
    Run Django's CSRF validation against *request*.

    The registration view itself is ``csrf_exempt`` (CSRF is pointless for the
    anonymous / ``Authorization``-header requests the endpoint is designed for),
    so permission classes that accept session-cookie authentication must call
    this to keep those browser-credentialed requests CSRF-protected.

    Returns ``True`` when the request passes CSRF validation.
    """
    check = _CsrfCheck(lambda req: None)
    check.process_request(request)
    return check.process_view(request, None, (), {}) is None


class IsAuthenticatedDCRPermission:
    """
    Allow registration only to session-authenticated users (default).

    Requests authenticated via the session cookie must also pass Django's
    CSRF validation, since the view itself is ``csrf_exempt``. Requests
    carrying a ``Bearer`` ``Authorization`` header are not CSRF-exposed
    (browsers never attach that header cross-site) and are checked for
    authentication only. Other schemes such as ``Basic`` do not bypass CSRF,
    because browsers can replay cached Basic credentials on cross-site
    requests just like cookies.
    """

    def has_permission(self, request) -> bool:
        if not (request.user and request.user.is_authenticated):
            return False
        if parse_bearer_token(request.META.get("HTTP_AUTHORIZATION", "")) is not None:
            return True
        return enforce_csrf(request)


class AllowAllDCRPermission:
    """Allow registration to anyone (open registration)."""

    def has_permission(self, request) -> bool:
        return True
