from django.conf import settings
from django.db import models


class UserProfile(models.Model):
    """
    Standard OIDC claims the stock Django user model has no field for.

    Feeds the ``email_verified``, ``phone_number``, ``phone_number_verified`` and
    ``address`` claims of the ``email``, ``phone`` and ``address`` scopes (OIDC Core
    §5.1, §5.4); see ``idp.oauth.CustomOAuth2Validator.get_additional_claims``.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="oidc_profile"
    )
    email_verified = models.BooleanField(default=False)
    # E.164 format is recommended by OIDC Core §5.1, e.g. "+1 (425) 555-1212".
    phone_number = models.CharField(max_length=32, blank=True)
    phone_number_verified = models.BooleanField(default=False)
    street_address = models.TextField(blank=True)
    locality = models.CharField(max_length=255, blank=True)
    region = models.CharField(max_length=255, blank=True)
    postal_code = models.CharField(max_length=32, blank=True)
    country = models.CharField(max_length=255, blank=True)

    def __str__(self) -> str:
        return f"OIDC profile of {self.user}"

    def address_claim(self) -> dict | None:
        """The ``address`` claim (OIDC Core §5.1.1), or ``None`` when no part is set."""
        parts = {
            "street_address": self.street_address,
            "locality": self.locality,
            "region": self.region,
            "postal_code": self.postal_code,
            "country": self.country,
        }
        parts = {k: v for k, v in parts.items() if v}
        if not parts:
            return None
        locality_line = " ".join(v for v in (self.locality, self.region, self.postal_code) if v)
        lines = [self.street_address, locality_line, self.country]
        return {"formatted": "\n".join(line for line in lines if line), **parts}
