import functools
import random

from django.conf import settings
from jwcrypto import jwk
from oauthlib.common import Request


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


def user_code_generator(user_code_length: int = 8) -> str:
    """
    Recommended user code that retains enough entropy but doesn't
    ruin the user experience of typing the code in.

    the below is based off:
    https://datatracker.ietf.org/doc/html/rfc8628#section-5.1
    but with added explanation as to where 34.5 bits of entropy is coming from

    entropy (in bits) = length of user code * log2(length of set of chars)
    e = 8 * log2(20)
    e = 34.5

    log2(20) is used here to say "you can make 20 yes/no decisions per user code single input character".

    _ _ _ _ - _ _ _ _ = 20^8 ~= 2^35.5
    *

    * you have 20 choices of chars to choose from (20 yes no decisions)
    and so on for the other 7 spaces

    in english this means an attacker would need to try
    2^34.5 unique combinations to exhaust all possibilities.
    however with a user code only being valid for 30 seconds
    and rate limiting, a brute force attack is extremely unlikely
    to work

    for our function we'll be using a base 32 character set
    """
    if user_code_length < 1:
        raise ValueError("user_code_length needs to be greater than 0")

    # base32 character space
    character_space = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

    # being explicit with length
    user_code = [""] * user_code_length

    for i in range(user_code_length):
        user_code[i] = random.choice(character_space)

    return "".join(user_code)


def set_oauthlib_user_to_device_request_user(request: Request) -> None:
    """
    The user isn't known when the device flow is initiated by a device.
    All we know is the client_id.

    However, when the user logins in order to submit the user code
    from the device we now know which user is trying to authenticate
    their device. We update the device user field at this point
    and save it in the db.

    This function is added to the pre_token stage during the device code grant's
    create_token_response where we have the oauthlib Request object which is what's used
    to populate the user field in the device model
    """
    # Since this function is used in the settings module, it will lead to circular imports
    # since django isn't fully initialised yet when settings run
    from oauth2_provider.models import DeviceGrant, get_device_grant_model

    device: DeviceGrant = get_device_grant_model().objects.get(device_code=request._params["device_code"])
    request.user = device.user
