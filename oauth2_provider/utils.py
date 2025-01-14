import functools
import random

from django.conf import settings
from jwcrypto import jwk


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

    # base32 character space
    character_space = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

    # being explicit with length
    user_code = [""] * user_code_length

    for i in range(user_code_length):
        user_code[i] = random.choice(character_space)

    return "".join(user_code)
