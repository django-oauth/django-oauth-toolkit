"""Unit tests for :mod:`oauth2_provider.authorization_server.stored_requests`.

The pushed authorization request tests drive the store end to end through the PAR and
authorization endpoints; these pin the store's own API.
"""

from datetime import timedelta

import pytest
from django.utils import timezone

from oauth2_provider.authorization_server.stored_requests import (
    REQUEST_URI_PREFIX,
    StoredAuthorizationRequestError,
    consume_authorization_request,
    is_stored_request_uri,
    store_authorization_request,
)
from oauth2_provider.models import get_stored_authorization_request_model


PARAMETERS = {"client_id": "client", "response_type": "code", "resource": ["https://a", "https://b"]}


@pytest.mark.parametrize(
    "value, expected",
    [
        (f"{REQUEST_URI_PREFIX}abc", True),
        (REQUEST_URI_PREFIX, True),
        ("https://rp.example/request.jwt", False),
        ("urn:ietf:params:oauth:something_else:abc", False),
        ("", False),
        (None, False),
    ],
)
def test_is_stored_request_uri(value, expected):
    assert is_stored_request_uri(value) is expected


@pytest.mark.django_db(databases="__all__")
def test_store_uses_the_given_lifetime_and_binds_the_client():
    before = timezone.now()
    request_uri = store_authorization_request("client", PARAMETERS, expires_in=300)

    assert request_uri.startswith(REQUEST_URI_PREFIX)
    record = get_stored_authorization_request_model().objects.get(request_uri=request_uri)
    assert record.client_id == "client"
    assert record.parameters == PARAMETERS
    assert before + timedelta(seconds=300) <= record.expires <= timezone.now() + timedelta(seconds=300)


@pytest.mark.django_db(databases="__all__")
def test_each_stored_request_gets_its_own_unguessable_reference():
    first = store_authorization_request("client", PARAMETERS, expires_in=60)
    second = store_authorization_request("client", PARAMETERS, expires_in=60)

    assert first != second
    # 32 random bytes, base64url-encoded (RFC 9126 section 2.2 / section 7.1).
    assert len(first) - len(REQUEST_URI_PREFIX) >= 43


@pytest.mark.django_db(databases="__all__")
def test_consume_returns_the_parameters_once():
    request_uri = store_authorization_request("client", PARAMETERS, expires_in=60)

    assert consume_authorization_request(request_uri, "client") == PARAMETERS
    with pytest.raises(StoredAuthorizationRequestError, match="already been used"):
        consume_authorization_request(request_uri, "client")


@pytest.mark.django_db(databases="__all__")
def test_consume_by_another_client_leaves_the_request_in_place():
    request_uri = store_authorization_request("client", PARAMETERS, expires_in=60)

    with pytest.raises(StoredAuthorizationRequestError, match="not issued to this client") as excinfo:
        consume_authorization_request(request_uri, "another-client")
    assert excinfo.value.error == "invalid_request"
    assert consume_authorization_request(request_uri, "client") == PARAMETERS


@pytest.mark.django_db(databases="__all__")
def test_consume_of_an_expired_request_fails_and_removes_it():
    request_uri = store_authorization_request("client", PARAMETERS, expires_in=-1)

    with pytest.raises(StoredAuthorizationRequestError, match="expired"):
        consume_authorization_request(request_uri, "client")
    assert not get_stored_authorization_request_model().objects.filter(request_uri=request_uri).exists()
