"""
OpenID Connect Back-Channel Logout 1.0, end to end.

The OP is a live ``tests/app/idp`` instance and the Relying Party is a loopback endpoint
that records what arrives at its ``backchannel_logout_uri``. That mirrors how the OpenID
Foundation's Back-Channel Logout OP profile tests an implementation -- the certification
suite registers its own endpoint and asserts on the Logout Token it receives -- so these
tests cover the same ground without needing the public ingress that suite requires.

What the certification profile additionally exercises and this cannot: it configures
``backchannel_logout_session_required: true``, which asks for a ``sid`` claim DOT does
not issue. See ``docs/oidc.rst``.
"""

import time

import pytest

from tests.e2e import constants as c
from tests.e2e.helpers.jwt_tools import (
    decode_claims_unverified,
    decode_header,
    validate_logout_token,
)
from tests.e2e.helpers.oauth_client import token_data


SPEC = "OpenID Connect Back-Channel Logout 1.0"
EVENT = "http://schemas.openid.net/event/backchannel-logout"


def _logout(oauth, session, id_token):
    return oauth.rp_logout(
        session,
        id_token_hint=id_token,
        post_logout_redirect_uri=c.POST_LOGOUT_REDIRECT_URI,
        state="s",
    )


@pytest.mark.compliance(SPEC, "2.1", "backchannel_logout_supported in OIDC discovery")
def test_discovery_advertises_back_channel_logout(backchannel_oauth):
    data = backchannel_oauth.discovery().json()
    assert data["backchannel_logout_supported"] is True
    # SHOULD also be registered; false is the spec's own default and is what DOT can
    # honestly claim until it models sessions.
    assert data["backchannel_logout_session_supported"] is False


@pytest.mark.compliance(SPEC, "5.2.1", "backchannel_logout_supported in RFC 8414 metadata")
def test_rfc8414_metadata_advertises_back_channel_logout(backchannel_oauth):
    data = backchannel_oauth.oauth_metadata().json()
    assert data["backchannel_logout_supported"] is True
    assert data["backchannel_logout_session_supported"] is False


@pytest.mark.compliance(SPEC, "2.5", "POST to the backchannel_logout_uri")
def test_logout_posts_a_logout_token_to_the_relying_party(backchannel_oauth, logout_receiver, logged_in):
    session, id_token = logged_in

    response = _logout(backchannel_oauth, session, id_token)
    assert response.status_code == 302

    requests_received = logout_receiver.wait_for(1)
    assert len(requests_received) == 1
    request = requests_received[0]
    # Section 2.5: an application/x-www-form-urlencoded POST carrying logout_token.
    assert "application/x-www-form-urlencoded" in request["content_type"]
    assert "logout_token" in request["form"]


@pytest.mark.compliance(SPEC, "2.4", "Logout Token claims")
@pytest.mark.compliance(SPEC, "2.6", "Logout Token validates RP-side")
def test_logout_token_passes_section_2_6_validation(
    backchannel_oauth, backchannel_idp, backchannel_client, logout_receiver, logged_in
):
    session, id_token = logged_in
    _logout(backchannel_oauth, session, id_token)
    logout_receiver.wait_for(1)

    token = logout_receiver.logout_tokens()[0]
    claims = validate_logout_token(token, backchannel_idp.issuer, backchannel_client["client_id"])

    # Section 2.4: the events member value SHOULD be the empty JSON object.
    assert claims["events"][EVENT] == {}
    # No sid, consistent with backchannel_logout_session_supported being false, so the
    # token identifies the subject only.
    assert claims["sub"]
    assert "sid" not in claims


@pytest.mark.compliance(SPEC, "2.4", "Logout Token is explicitly typed")
def test_logout_token_is_explicitly_typed(backchannel_oauth, logout_receiver, logged_in):
    # Section 2.4 RECOMMENDS explicit typing and section 4.1 explains why: it keeps a
    # Logout Token from being repurposed as an ID Token.
    session, id_token = logged_in
    _logout(backchannel_oauth, session, id_token)
    logout_receiver.wait_for(1)

    header = decode_header(logout_receiver.logout_tokens()[0])
    assert header["typ"] == "logout+jwt"
    assert header["alg"] == "RS256"


@pytest.mark.compliance(SPEC, "4", "Short Logout Token expiry")
def test_logout_token_expires_within_two_minutes(
    backchannel_oauth, backchannel_idp, backchannel_client, logout_receiver, logged_in
):
    # Section 4: "OPs are encouraged to use short expiration times in Logout Tokens,
    # preferably at most two minutes in the future".
    session, id_token = logged_in
    _logout(backchannel_oauth, session, id_token)
    logout_receiver.wait_for(1)

    claims = validate_logout_token(
        logout_receiver.logout_tokens()[0], backchannel_idp.issuer, backchannel_client["client_id"]
    )
    assert claims["exp"] - claims["iat"] <= 120
    assert claims["exp"] - int(time.time()) <= 120


@pytest.mark.compliance(SPEC, "2.4", "jti identifies the Logout Token, not the ID Token")
def test_logout_token_jti_is_not_the_id_tokens_jti(
    backchannel_oauth, backchannel_idp, backchannel_client, logout_receiver, logged_in
):
    # Section 2.4 requires jti to be a "unique identifier for the token" -- this token,
    # not the ID Token that prompted it. Reusing the ID Token's jti is stable for that
    # token's lifetime, so a second logout for the same ID Token looks like a replay to
    # any RP doing the section 2.6 step 8 check. Comparing two Logout Tokens cannot
    # catch this (each login mints a fresh ID Token), so compare against the source.
    session, id_token = logged_in
    _logout(backchannel_oauth, session, id_token)
    logout_receiver.wait_for(1)

    claims = validate_logout_token(
        logout_receiver.logout_tokens()[0], backchannel_idp.issuer, backchannel_client["client_id"]
    )
    id_token_jti = decode_claims_unverified(id_token).get("jti")
    assert id_token_jti, "ID Token carries no jti to compare against"
    assert claims["jti"] != id_token_jti, (
        "the Logout Token reused the ID Token's jti; an RP performing section 2.6 "
        "step 8 would drop a later logout for this session as a replay"
    )


@pytest.mark.compliance(SPEC, "2.4", "jti is unique across Logout Tokens")
def test_each_logout_token_carries_a_fresh_jti(
    backchannel_oauth, backchannel_idp, backchannel_client, logout_receiver, logged_in
):
    # Section 2.4 requires jti to be a "unique identifier for the token", and section
    # 2.6 step 8 lets an RP drop a jti it has seen before. Two logouts for the same user
    # must therefore not reuse one -- notably not the ID Token's own jti.
    session, id_token = logged_in
    _logout(backchannel_oauth, session, id_token)
    logout_receiver.wait_for(1)

    # Log in again and repeat: a second session for the same subject at the same RP.
    second_session = backchannel_oauth.login(c.E2E_USERNAME, c.E2E_PASSWORD)
    result = backchannel_oauth.authorize(
        second_session,
        client_id=backchannel_client["client_id"],
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s2",
    )
    second_id_token = token_data(
        backchannel_oauth.exchange_code(
            client_id=backchannel_client["client_id"],
            code=result.query_params["code"],
            redirect_uri=c.REDIRECT_URI,
            client_secret=backchannel_client["client_secret"],
        )
    )["id_token"]
    _logout(backchannel_oauth, second_session, second_id_token)
    logout_receiver.wait_for(2)

    jtis = [
        validate_logout_token(token, backchannel_idp.issuer, backchannel_client["client_id"])["jti"]
        for token in logout_receiver.logout_tokens()
    ]
    assert len(jtis) == 2
    assert jtis[0] != jtis[1], "two Logout Tokens shared a jti; an RP would drop the second"


@pytest.mark.compliance(SPEC, "2.3", "Only relying parties with a live session")
def test_no_logout_token_for_a_relying_party_the_user_never_visited(backchannel_oauth, logout_receiver):
    # The OP must notify the RPs the user is logged in to, not every registered RP. The
    # shared confidential client has no backchannel_logout_uri, so logging out of it
    # must produce nothing at this receiver.
    logout_receiver.reset()
    session = backchannel_oauth.login(c.E2E_USERNAME, c.E2E_PASSWORD)
    result = backchannel_oauth.authorize(
        session,
        client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    other_id_token = token_data(
        backchannel_oauth.exchange_code(
            client_id=c.CONFIDENTIAL_CODE_CLIENT_ID,
            code=result.query_params["code"],
            redirect_uri=c.REDIRECT_URI,
            client_secret=c.CONFIDENTIAL_CODE_SECRET,
        )
    )["id_token"]

    response = _logout(backchannel_oauth, session, other_id_token)
    assert response.status_code == 302
    # Give a stray dispatch time to arrive before concluding none did.
    time.sleep(1)
    assert logout_receiver.received == []


@pytest.mark.compliance(SPEC, "2.5", "A failing relying party cannot block the logout")
def test_logout_completes_when_the_relying_party_rejects_the_token(
    backchannel_oauth, backchannel_client, logout_receiver, logged_in
):
    # Delivery is best-effort. With the endpoint answering 400 -- section 2.8's failure
    # response -- the logout must still succeed and the OP session must still be gone.
    session, id_token = logged_in
    logout_receiver.response_status = 400

    response = _logout(backchannel_oauth, session, id_token)
    assert response.status_code == 302
    assert response.headers["Location"].startswith(c.POST_LOGOUT_REDIRECT_URI)
    # The OP did try, and the RP did refuse.
    logout_receiver.wait_for(1)

    # The OP session is really ended: a fresh authorization now has to log in again.
    result = backchannel_oauth.authorize(
        session,
        client_id=backchannel_client["client_id"],
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    )
    assert "code" not in result.query_params
