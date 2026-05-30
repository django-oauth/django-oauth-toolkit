import uuid

from django.db import models

from oauth2_provider.models import (
    AbstractAccessToken,
    AbstractApplication,
    AbstractDeviceGrant,
    AbstractGrant,
    AbstractIDToken,
    AbstractRefreshToken,
)
from oauth2_provider.settings import oauth2_settings


class BaseTestApplication(AbstractApplication):
    allowed_schemes = models.TextField(blank=True)

    def get_allowed_schemes(self):
        if self.allowed_schemes:
            return self.allowed_schemes.split()
        return super().get_allowed_schemes()


class SampleApplication(AbstractApplication):
    custom_field = models.CharField(max_length=255)


class SampleAccessToken(AbstractAccessToken):
    custom_field = models.CharField(max_length=255)
    source_refresh_token = models.OneToOneField(
        # unique=True implied by the OneToOneField
        oauth2_settings.REFRESH_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="s_refreshed_access_token",
    )
    id_token = models.OneToOneField(
        oauth2_settings.ID_TOKEN_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="s_access_token",
    )


class SampleRefreshToken(AbstractRefreshToken):
    custom_field = models.CharField(max_length=255)
    access_token = models.OneToOneField(
        oauth2_settings.ACCESS_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="s_refresh_token",
    )


class SampleGrant(AbstractGrant):
    custom_field = models.CharField(max_length=255)


class SampleDeviceGrant(AbstractDeviceGrant):
    custom_field = models.CharField(blank=True, default="", max_length=255)

    class Meta(AbstractDeviceGrant.Meta):
        swappable = "OAUTH2_PROVIDER_DEVICE_GRANT_MODEL"


class LocalIDToken(AbstractIDToken):
    """Exists to be improperly configured for multiple databases."""

    # The other token types will be in 'alpha' database.


class CustomPkAccessToken(AbstractAccessToken):
    """AccessToken with a custom (non-``id``) primary key.

    Used to verify that ``clear_expired()`` and ``RefreshToken.revoke()`` do
    not assume the primary key field is named ``id``.
    See https://github.com/django-oauth/django-oauth-toolkit/pull/1593
    """

    id = None
    source_refresh_token = None
    id_token = None
    custom_pk = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)


class CustomPkRefreshToken(AbstractRefreshToken):
    """RefreshToken with a custom (non-``id``) primary key."""

    id = None
    custom_pk = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_token = models.OneToOneField(
        CustomPkAccessToken,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refresh_token",
    )
