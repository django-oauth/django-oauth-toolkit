import functools
import secrets

from django.conf import settings
from jwcrypto import jwk
from oauthlib.common import Request


def parse_bearer_token(auth_header):
    """
    Extract the token from a Bearer ``Authorization`` header value.

    Implements RFC 7235 / RFC 6750 semantics: the scheme match is
    case-insensitive ("bearer", "Bearer" and "BEARER" are all accepted) and
    exact (schemes that merely start with "Bearer", e.g. "BearerX", are
    rejected), and any whitespace runs around the scheme and token are
    tolerated. RFC 6750 Bearer credentials are a single ``token68`` value and
    cannot contain whitespace, so values with more than one whitespace-separated
    part after the scheme (e.g. "Bearer token extra") are rejected.

    Return the token string, or ``None`` if the header is not a well-formed
    Bearer authorization.
    """
    if not auth_header:
        return None
    # maxsplit=2 (not 1) so whitespace inside the credentials produces a third
    # element and fails the length check — a token68 value cannot contain
    # whitespace — while still bounding the work on long malformed headers.
    splits = auth_header.split(maxsplit=2)
    if len(splits) != 2 or splits[0].lower() != "bearer":
        return None
    return splits[1]


@functools.lru_cache()
def jwk_from_pem(pem_string):
    """
    A cached version of jwcrypto.JWK.from_pem.
    Converting from PEM is expensive for large keys such as those using RSA.
    """
    return jwk.JWK.from_pem(pem_string.encode("utf-8"))


def get_timezone(time_zone):
    """
    Return the given time zone name as a tzinfo instance.
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

    This follows the guidance in:
    https://datatracker.ietf.org/doc/html/rfc8628#section-5.1
    with an explanation of the entropy this implementation provides.

    entropy (in bits) = length of user code * log2(size of the character set)

    This implementation uses a 32-character (RFC 4648 Base32hex, ``0-9A-V``)
    alphabet, so for the default length of 8 characters:

        e = 8 * log2(32) = 8 * 5 = 40 bits

    i.e. there are 32^8 == 2^40 possible codes. (The generated code is a plain
    string with no separator; any grouping/hyphenation is a presentation concern
    for the UI, not part of the value.)

    An attacker would need to try up to 2^40 combinations to exhaust the space.
    The device grant does expire (its validity window is enforced), but this
    library does not itself rate-limit the verification step, so deployments
    should keep the code's validity window short and rate-limit the verification
    endpoint to make brute-forcing impractical.

    The code is drawn from ``secrets`` (a CSPRNG) rather than ``random`` so
    that the ``user_code`` is unguessable, as required for device-flow
    credentials by RFC 8628 sections 5.1 and 5.2.
    """
    if user_code_length < 1:
        raise ValueError("user_code_length needs to be greater than 0")

    # base32 character space
    character_space = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

    # being explicit with length
    user_code = [""] * user_code_length

    for i in range(user_code_length):
        user_code[i] = secrets.choice(character_space)

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
    from oauth2_provider.models import AbstractDeviceGrant, get_device_grant_model

    device: AbstractDeviceGrant = get_device_grant_model().objects.get(
        device_code=request._params["device_code"]
    )
    request.user = device.user
    request.scopes = device.scope.split() if device.scope else []
