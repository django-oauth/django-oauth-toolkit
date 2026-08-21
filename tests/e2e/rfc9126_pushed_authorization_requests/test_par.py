"""
RFC 9126 — OAuth 2.0 Pushed Authorization Requests (PAR).

Exercised end-to-end against the live IdP with a confidential client. PAR is a
back-channel flow: the client first pushes the authorization request parameters
directly to the ``/o/par/`` endpoint (authenticating like at the token endpoint)
and receives a single-use ``request_uri``; the user agent then carries only
``client_id`` + ``request_uri`` to the authorization endpoint. These tests drive
that full flow — push, browser-style login/consent, authorization response, and
the token exchange — plus the endpoint's key error behaviours.
"""

import pytest

from tests.e2e import constants as c


REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


@pytest.mark.compliance("RFC 9126", "2.2", "Successful Response")
def test_par_endpoint_returns_request_uri(oauth):
    """The PAR endpoint returns a 201 with a single-use ``request_uri`` + ``expires_in``."""
    resp = oauth.pushed_authorization_request(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid read",
        state="par-state",
    )
    assert resp.status_code == 201, resp.text
    assert resp.headers.get("Cache-Control") == "no-cache, no-store"
    body = resp.json()
    assert body["request_uri"].startswith(REQUEST_URI_PREFIX)
    assert body["expires_in"] > 0


@pytest.mark.compliance("RFC 9126", "2.3", "Error Response")
def test_par_endpoint_requires_client_authentication(oauth):
    """An unauthenticated push is rejected with ``invalid_client`` (401)."""
    resp = oauth.pushed_authorization_request(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["error"] == "invalid_client"
    # RFC 6749 §5.2: a 401 client-authentication failure carries a challenge.
    assert 'error="invalid_client"' in resp.headers.get("WWW-Authenticate", "")


@pytest.mark.compliance("RFC 9126", "2.1", "Request")
def test_par_endpoint_rejects_request_uri(oauth):
    """A pushed request must not itself carry a ``request_uri`` (RFC 9126 §2.1)."""
    resp = oauth.pushed_authorization_request(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        extra={"request_uri": f"{REQUEST_URI_PREFIX}abc"},
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.compliance("RFC 9126", "2.1", "Request")
@pytest.mark.compliance("RFC 9126", "4", "Authorization Request")
def test_par_end_to_end_pushed_request_is_authorized_and_exchanged(oauth, user_session, issuer):
    """Push, then complete the authorization + token exchange via the request_uri."""
    push = oauth.pushed_authorization_request(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid read",
        state="par-e2e-state",
    )
    assert push.status_code == 201, push.text
    request_uri = push.json()["request_uri"]

    # The user agent carries only client_id + request_uri to the authorization endpoint.
    result = oauth.authorize(
        user_session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        request_uri=request_uri,
    )
    assert result.status_code == 302, result
    assert result.location.startswith(c.REDIRECT_URI)
    assert result.query_params["state"] == "par-e2e-state", "pushed state must be preserved"
    code = result.query_params.get("code")
    assert code, "authorization code MUST be present"

    token_resp = oauth.exchange_code(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        code=code,
        redirect_uri=c.REDIRECT_URI,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
    )
    assert token_resp.status_code == 200, token_resp.text
    body = token_resp.json()
    assert body["token_type"].lower() == "bearer"
    assert body["access_token"]
    assert "read" in body["scope"].split()


@pytest.mark.compliance("RFC 9126", "4", "Authorization Request")
def test_request_uri_is_single_use(oauth, user_session):
    """A ``request_uri`` is consumed on first use and rejected on reuse (RFC 9126 §4 / §7.3)."""
    push = oauth.pushed_authorization_request(
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        client_secret=c.CONFIDENTIAL_CODE_SECRET,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="once",
    )
    request_uri = push.json()["request_uri"]

    first = oauth.authorize(user_session, client_id=c.CONFIDENTIAL_CODE_CLIENT_ID, request_uri=request_uri)
    assert first.status_code == 302
    assert first.query_params.get("code")

    second = oauth.authorize(user_session, client_id=c.CONFIDENTIAL_CODE_CLIENT_ID, request_uri=request_uri)
    # The consumed request_uri no longer resolves: the authorization endpoint
    # renders a non-redirecting error rather than issuing a second code.
    assert second.status_code != 302
