"""
Permission classes for the Dynamic Client Registration endpoint (RFC 7591).

Each class must implement ``has_permission(request) -> bool``.
Configure via ``OAUTH2_PROVIDER["DCR_REGISTRATION_PERMISSION_CLASSES"]``.
"""


class IsAuthenticatedDCRPermission:
    """Allow registration only to session-authenticated users (default)."""

    def has_permission(self, request) -> bool:
        return bool(request.user and request.user.is_authenticated)


class AllowAllDCRPermission:
    """Allow registration to anyone (open registration)."""

    def has_permission(self, request) -> bool:
        return True
