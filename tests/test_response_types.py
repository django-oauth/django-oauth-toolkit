import pytest

from oauth2_provider.authorization_server.response_types import (
    canonical_response_type,
    canonicalize_response_type_parameter,
)


# The response types oauthlib's OpenID Connect server registers.
REGISTERED = (
    "code",
    "code id_token",
    "code id_token token",
    "code token",
    "id_token",
    "id_token token",
    "none",
    "token",
)


@pytest.mark.parametrize(
    "response_type, expected",
    [
        # Registered values are kept as they are.
        ("code", "code"),
        ("none", "none"),
        ("code id_token token", "code id_token token"),
        # Any other ordering maps to the registered one (RFC 6749 §3.1.1).
        ("id_token code", "code id_token"),
        ("token code", "code token"),
        ("token id_token", "id_token token"),
        ("token id_token code", "code id_token token"),
        ("id_token token code", "code id_token token"),
        # Values that are not a permutation of a registered one are left alone.
        (None, None),
        ("", ""),
        ("code foo", "code foo"),
        ("Code", "Code"),
        ("code id_token token foo", "code id_token token foo"),
        # A repeated name or an empty one is not a valid response-type (RFC 6749 A.3).
        ("id_token code code", "id_token code code"),
        ("code code", "code code"),
        ("id_token  code", "id_token  code"),
        (" id_token code", " id_token code"),
        ("id_token code ", "id_token code "),
        ("id_token\tcode", "id_token\tcode"),
    ],
)
def test_canonical_response_type(response_type, expected):
    assert canonical_response_type(response_type, REGISTERED) == expected


def test_canonical_response_type_without_a_registry():
    assert canonical_response_type("id_token code", ()) == "id_token code"


@pytest.mark.parametrize(
    "encoded, expected",
    [
        ("", ""),
        ("client_id=abc&state=xyz", "client_id=abc&state=xyz"),
        ("response_type=code&state=xyz", "response_type=code&state=xyz"),
        ("response_type=code+id_token&state=xyz", "response_type=code+id_token&state=xyz"),
        # Only response_type is rewritten; every other pair keeps its encoding.
        (
            "client_id=abc&response_type=id_token+code&state=a%2Bb&redirect_uri=http%3A%2F%2Fexample.org",
            "client_id=abc&response_type=code%20id_token&state=a%2Bb&redirect_uri=http%3A%2F%2Fexample.org",
        ),
        ("response_type=token%20id_token", "response_type=id_token%20token"),
        ("response%5Ftype=token%20id_token", "response%5Ftype=id_token%20token"),
        # A repeated parameter stays repeated, so oauthlib still rejects the duplicate.
        (
            "response_type=id_token+code&response_type=code",
            "response_type=code%20id_token&response_type=code",
        ),
        # Unknown values, and pairs without a value, are left alone.
        ("response_type=code+foo", "response_type=code+foo"),
        ("response_type&state=xyz", "response_type&state=xyz"),
        ("response_type=", "response_type="),
    ],
)
def test_canonicalize_response_type_parameter(encoded, expected):
    assert canonicalize_response_type_parameter(encoded, REGISTERED) == expected
