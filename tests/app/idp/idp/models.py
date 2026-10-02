from django.conf import settings
from django.db import models


class UserProfile(models.Model):
    """
    Standard OIDC claims the stock Django user model has no field for.

    Feeds the ``profile``-scope claims beyond the user's names, and the
    ``email_verified``, ``phone_number``, ``phone_number_verified`` and ``address``
    claims of the ``email``, ``phone`` and ``address`` scopes (OIDC Core §5.1, §5.4);
    see ``idp.oauth.CustomOAuth2Validator.get_additional_claims``.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="oidc_profile"
    )
    # profile scope
    middle_name = models.CharField(max_length=150, blank=True)
    nickname = models.CharField(max_length=150, blank=True)
    profile = models.URLField(blank=True)
    picture = models.URLField(blank=True)
    website = models.URLField(blank=True)
    gender = models.CharField(max_length=64, blank=True)
    birthdate = models.DateField(null=True, blank=True)
    # IANA time zone, e.g. "Europe/Paris"; BCP 47 language tag, e.g. "en-US".
    zoneinfo = models.CharField(max_length=64, blank=True)
    locale = models.CharField(max_length=35, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    # email scope
    email_verified = models.BooleanField(default=False)
    # phone scope
    # E.164 format is recommended by OIDC Core §5.1, e.g. "+1 (425) 555-1212".
    phone_number = models.CharField(max_length=32, blank=True)
    phone_number_verified = models.BooleanField(default=False)
    # address scope
    street_address = models.TextField(blank=True)
    locality = models.CharField(max_length=255, blank=True)
    region = models.CharField(max_length=255, blank=True)
    postal_code = models.CharField(max_length=32, blank=True)
    country = models.CharField(max_length=255, blank=True)

    def __str__(self) -> str:
        return f"OIDC profile of {self.user}"

    def profile_claims(self) -> dict:
        """The ``profile`` scope claims held here, omitting those with no value."""
        claims = {
            "middle_name": self.middle_name,
            "nickname": self.nickname,
            "profile": self.profile,
            "picture": self.picture,
            "website": self.website,
            "gender": self.gender,
            # ISO 8601 YYYY-MM-DD (OIDC Core §5.1).
            "birthdate": self.birthdate.isoformat() if self.birthdate else "",
            "zoneinfo": self.zoneinfo,
            "locale": self.locale,
        }
        claims = {k: v for k, v in claims.items() if v}
        # Seconds since the epoch (OIDC Core §5.1).
        claims["updated_at"] = int(self.updated_at.timestamp())
        return claims

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
