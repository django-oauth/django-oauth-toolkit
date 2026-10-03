"""
Fixtures for the back-channel logout package: a loopback logout endpoint plus a relying
party registered to use it.

The endpoint binds an arbitrary free port, so the client that points at it cannot come
from a checked-in fixture. It registers itself instead, through Dynamic Client
Registration, which also exercises the ``backchannel_logout_uri`` member Back-Channel
Logout 1.0 section 5.1.1 registers for that purpose: a client whose logout URI the OP
learned the way a real relying party would.

The demo IdP defaults ``OIDC_BACKCHANNEL_LOGOUT_ENABLED``,
``OIDC_RP_INITIATED_LOGOUT_ENABLED`` and ``DCR_ENABLED`` on, so no IdP behaviour is
special-cased for these tests.
"""

import pytest
import requests

from tests.e2e import constants as c
from tests.e2e.helpers.backchannel_receiver import BackchannelLogoutReceiver
from tests.e2e.helpers.idp_process import IdpServer
from tests.e2e.helpers.oauth_client import OAuthClient, token_data


@pytest.fixture(scope="session")
def logout_receiver():
    """The relying party's back-channel logout endpoint, on the loopback interface."""
    receiver = BackchannelLogoutReceiver().start()
    try:
        yield receiver
    finally:
        receiver.stop()


@pytest.fixture(scope="session")
def backchannel_idp():
    server = IdpServer(
        scopes=c.E2E_SCOPES,
        default_scopes=c.E2E_DEFAULT_SCOPES,
        pkce_required=False,
        pkce_required_client_ids=c.PKCE_REQUIRED_CLIENT_IDS,
    )
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def backchannel_oauth(backchannel_idp):
    return OAuthClient(backchannel_idp.base_url)


@pytest.fixture(scope="session")
def backchannel_client(backchannel_oauth, logout_receiver):
    """Register a relying party whose backchannel_logout_uri is the receiver.

    A registration gets an RS256 signing algorithm by default, so the client can be
    issued the ID Tokens the OP reads to decide whom to notify.
    """
    response = requests.post(
        backchannel_oauth.url("/o/register/"),
        json={
            "client_name": "E2E Back-Channel Logout",
            "redirect_uris": [c.REDIRECT_URI],
            "post_logout_redirect_uris": [c.POST_LOGOUT_REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_basic",
            "backchannel_logout_uri": logout_receiver.uri,
        },
        timeout=10,
    )
    assert response.status_code == 201, response.text
    registered = response.json()
    # The OP accepted and stored the logout URI, and says so in the response.
    assert registered["backchannel_logout_uri"] == logout_receiver.uri
    # And says it will not send a sid, which this OP does not issue.
    assert registered["backchannel_logout_session_required"] is False
    # And provisioned a signing algorithm, without which there would be no ID Token and
    # so nothing for a logout to notify about.
    assert registered["id_token_signed_response_alg"] == "RS256"
    return registered


@pytest.fixture
def logged_in(backchannel_oauth, backchannel_client, logout_receiver):
    """Log in, obtain an ID Token for the back-channel client, and clear the receiver.

    Returns ``(session, id_token)``. The receiver is reset per test so each one asserts
    only on what its own logout produced.
    """
    logout_receiver.reset()
    session = backchannel_oauth.login(c.E2E_USERNAME, c.E2E_PASSWORD)
    result = backchannel_oauth.authorize(
        session,
        client_id=backchannel_client["client_id"],
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    tokens = token_data(
        backchannel_oauth.exchange_code(
            client_id=backchannel_client["client_id"],
            code=result.query_params["code"],
            redirect_uri=c.REDIRECT_URI,
            client_secret=backchannel_client["client_secret"],
        )
    )
    return session, tokens["id_token"]
