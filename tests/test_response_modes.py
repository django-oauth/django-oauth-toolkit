import pytest

from oauth2_provider.authorization_server import response_modes


@pytest.mark.parametrize(
    "response_type, response_mode, expected",
    [
        ("code", None, False),
        ("none", None, False),
        (None, None, False),
        ("token", None, True),
        ("id_token", None, True),
        ("id_token token", None, True),
        ("code id_token", None, True),
        ("code token", None, True),
        ("code id_token token", None, True),
        # query is rejected for fragment response types, so their errors stay in the fragment.
        ("id_token", "query", True),
        ("code token", "query", True),
        ("code", "query", False),
        ("code", "fragment", True),
        ("none", "fragment", True),
        ("code", "form_post", False),
    ],
)
def test_authorization_response_uses_fragment(response_type, response_mode, expected):
    assert response_modes.authorization_response_uses_fragment(response_type, response_mode) is expected


@pytest.mark.parametrize(
    "redirect_uri, response_type, response_mode, expected",
    [
        ("https://rp.example/cb", "code", None, "https://rp.example/cb?error=x"),
        ("https://rp.example/cb?foo=bar", "code", None, "https://rp.example/cb?foo=bar&error=x"),
        ("https://rp.example/cb", "code", "fragment", "https://rp.example/cb#error=x"),
        ("https://rp.example/cb", "id_token", None, "https://rp.example/cb#error=x"),
        ("https://rp.example/cb?foo=bar", "code token", None, "https://rp.example/cb?foo=bar#error=x"),
    ],
)
def test_add_params_to_authorization_redirect(redirect_uri, response_type, response_mode, expected):
    url = response_modes.add_params_to_authorization_redirect(
        redirect_uri, "error=x", response_type, response_mode
    )
    assert url == expected


@pytest.mark.parametrize(
    "response_type, response_mode, expected",
    [
        ("code", "query", True),
        ("code", "fragment", True),
        ("code", "form_post", False),
        ("id_token", "fragment", True),
        ("id_token", "query", False),
        ("code token", "query", False),
        ("id_token token", "form_post", False),
        ("code", "not-a-mode", False),
    ],
)
def test_response_mode_permitted(response_type, response_mode, expected):
    assert response_modes.response_mode_permitted(response_type, response_mode) is expected
