import functools
import hashlib

from django.conf import settings
from jwcrypto import jwk

from .settings import oauth2_settings


@functools.lru_cache()
def jwk_from_pem(pem_string):
    """
    A cached version of jwcrypto.JWK.from_pem.
    Converting from PEM is expensive for large keys such as those using RSA.
    """
    return jwk.JWK.from_pem(pem_string.encode("utf-8"))


# @functools.lru_cache
def get_timezone(time_zone):
    """
    Return the default time zone as a tzinfo instance.

    This is the time zone defined by settings.TIME_ZONE.
    """
    try:
        import zoneinfo
    except ImportError:
        import pytz

        return pytz.timezone(time_zone)
    else:
        if getattr(settings, "USE_DEPRECATED_PYTZ", False):
            import pytz

            return pytz.timezone(time_zone)
        return zoneinfo.ZoneInfo(time_zone)


def session_management_state_key(request):
    """
    Determine value to use as session state.
    """
    key = request.session.session_key or str(oauth2_settings.OIDC_SESSION_MANAGEMENT_DEFAULT_SESSION_KEY)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
