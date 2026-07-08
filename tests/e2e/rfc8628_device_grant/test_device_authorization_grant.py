"""RFC 8628 — OAuth 2.0 Device Authorization Grant."""

import pytest

from tests.e2e import constants as c


@pytest.mark.compliance("RFC 8628", "3.2", "Device Authorization Response")
def test_device_authorization_response_fields(oauth):
    resp = oauth.device_authorization(client_id=c.DEVICE_CLIENT_ID)
    assert resp.status_code == 200
    body = resp.json()
    assert body["device_code"]
    assert body["user_code"]
    assert body["verification_uri"]
    assert "expires_in" in body


@pytest.mark.compliance("RFC 8628", "3.5", "authorization_pending")
def test_polling_before_approval_is_authorization_pending(oauth):
    device = oauth.device_authorization(client_id=c.DEVICE_CLIENT_ID).json()
    resp = oauth.device_token(client_id=c.DEVICE_CLIENT_ID, device_code=device["device_code"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "authorization_pending"


@pytest.mark.compliance("RFC 8628", "3.3", "User Interaction")
@pytest.mark.compliance("RFC 8628", "3.5", "Device Access Token Response")
def test_device_flow_completes_after_user_approval(oauth, login):
    device = oauth.device_authorization(client_id=c.DEVICE_CLIENT_ID).json()

    session = login()  # resource owner authenticates at the verification URI
    approve = oauth.device_user_approve(session, user_code=device["user_code"], action="accept")
    assert approve.status_code in (301, 302)

    resp = oauth.device_token(client_id=c.DEVICE_CLIENT_ID, device_code=device["device_code"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["token_type"].lower() == "bearer"


@pytest.mark.compliance("RFC 8628", "3.5", "access_denied")
def test_device_flow_denied_returns_access_denied(oauth, login):
    device = oauth.device_authorization(client_id=c.DEVICE_CLIENT_ID).json()

    session = login()
    oauth.device_user_approve(session, user_code=device["user_code"], action="deny")

    resp = oauth.device_token(client_id=c.DEVICE_CLIENT_ID, device_code=device["device_code"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"
