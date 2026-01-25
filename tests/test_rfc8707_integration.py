import json
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from oauth2_provider.models import AccessToken, Grant, RefreshToken, get_application_model


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_authorization_code_flow_with_resource(client, oauth2_settings):
    """
    Integration test for RFC 8707 resource indicators in authorization code flow.

    Tests the complete flow:
    1. Authorization request with resource parameter
    2. User authorizes
    3. Token request with resource parameter
    4. Access token includes resource binding
    """

    User = get_user_model()
    Application = get_application_model()

    # Setup
    user = User.objects.create_user("flow_user", "test@example.com", "123456")

    # Store plaintext secret before it gets hashed
    plaintext_secret = "test-secret-456"

    app = Application.objects.create(
        name="MCP Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,  # Skip user consent for test
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization request with resource parameter
    auth_url = reverse("oauth2_provider:authorize")
    # In RFC 8707, multiple resource parameters are sent as repeated query parameters.
    # Django test client doesn't support multiple values in dict syntax
    # so we pass the full URL with query string
    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read write",
    }
    # Add multiple resource parameters
    query_string = (
        urlencode(params) + "&resource=https://api.example.com/mcp&resource=https://data.example.com/mcp"
    )
    auth_response = client.get(f"{auth_url}?{query_string}")

    # Should redirect with authorization code
    assert auth_response.status_code == 302
    redirect_url = auth_response.url
    assert "code=" in redirect_url

    # Extract authorization code
    code = redirect_url.split("code=")[1].split("&")[0]

    # Verify grant has resource stored
    grant = Grant.objects.get(code=code)
    grant_resources = grant.resource
    assert grant_resources == [
        "https://api.example.com/mcp",
        "https://data.example.com/mcp",
    ]

    # Step 2: Token request with resource parameter
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "resource": "https://api.example.com/mcp",  # Request subset of resources
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()
    assert "access_token" in token_data

    # Step 3: Verify access token has resource binding (JSON array format)
    access_token = AccessToken.objects.get(token=token_data["access_token"])
    token_resources = access_token.resource
    assert token_resources == ["https://api.example.com/mcp"]

    # Step 4: Verify audience validation
    assert access_token.allows_audience("https://api.example.com/mcp") is True
    assert access_token.allows_audience("https://data.example.com/mcp") is False
    assert access_token.allows_audience("https://evil.example.com") is False

    # Verify audience list
    assert access_token.resource == ["https://api.example.com/mcp"]


@pytest.mark.django_db
def test_rfc8707_client_credentials_flow_with_resource(client):
    """
    Integration test for RFC 8707 with client credentials grant.
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("creds_user", "test@example.com", "123456")

    # Store plaintext secret before it gets hashed
    plaintext_secret = "test-secret-123"

    app = Application.objects.create(
        name="Service Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        client_secret=plaintext_secret,
    )

    # Token request with resource parameter
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "client_credentials",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "scope": "read",
            "resource": "https://service.example.com/api",
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()

    access_token = AccessToken.objects.get(token=token_data["access_token"])

    # Verify resource is stored as JSON array

    token_resources = access_token.resource
    assert token_resources == ["https://service.example.com/api"]

    # Verify audience validation
    assert access_token.allows_audience("https://service.example.com/api") is True
    assert access_token.allows_audience("https://other.example.com") is False


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_implicit_flow_with_resource(client, oauth2_settings):
    """
    Integration test for RFC 8707 with implicit grant flow.

    Per RFC 8707: "When an access token will be returned directly from the
    authorization endpoint via the implicit flow, the requested resource is
    applicable to that access token."
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("implicit_user", "test@example.com", "123456")
    app = Application.objects.create(
        name="Implicit Client",
        user=user,
        client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_IMPLICIT,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
    )

    client.force_login(user)

    # Authorization request with response_type=token (implicit flow)
    auth_url = reverse("oauth2_provider:authorize")

    params = {
        "client_id": app.client_id,
        "response_type": "token",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/implicit"
    auth_response = client.get(f"{auth_url}?{query_string}")

    # Should redirect with access token in fragment
    assert auth_response.status_code == 302
    redirect_url = auth_response.url
    assert "#access_token=" in redirect_url

    # Extract access token from URL fragment
    fragment = urlparse(redirect_url).fragment
    fragment_params = parse_qs(fragment)
    access_token_value = fragment_params["access_token"][0]

    # Verify access token has resource binding

    access_token = AccessToken.objects.get(token=access_token_value)
    token_resources = access_token.resource
    assert token_resources == ["https://api.example.com/implicit"]

    # Verify audience validation
    assert access_token.allows_audience("https://api.example.com/implicit") is True
    assert access_token.allows_audience("https://other.example.com") is False


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_request_cannot_escalate_resources(client, oauth2_settings):
    """
    Test that token request cannot request resources not in the original authorization.

    Per RFC 8707: "policies...may limit the acceptable resources to those that
    were originally granted by the resource owner or a subset thereof."
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("escalation_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-789"

    app = Application.objects.create(
        name="Escalation Test Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization request with limited resources
    auth_url = reverse("oauth2_provider:authorize")
    from urllib.parse import urlencode

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/safe"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = auth_response.url.split("code=")[1].split("&")[0]

    # Step 2: Token request trying to escalate to unauthorized resource
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "resource": "https://evil.example.com/admin",  # NOT authorized!
        },
    )

    # Should reject this request with invalid_target error per RFC 8707
    assert token_response.status_code == 400

    # Parse the JSON response (Note: Content-Type may be incorrect due to oauthlib CustomOAuth2Error)
    import json as json_lib

    error_data = json_lib.loads(token_response.content)
    assert error_data["error"] == "invalid_target"
    assert (
        "cannot escalate resource permissions beyond the original authorization grant"
        in error_data["error_description"]
    )


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_request_without_resource_gets_all(client, oauth2_settings):
    """
    Test that token request without resource parameter gets all authorized resources.
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("all_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-def"

    app = Application.objects.create(
        name="All Resources Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization with multiple resources
    auth_url = reverse("oauth2_provider:authorize")

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = (
        urlencode(params) + "&resource=https://api.example.com/x&resource=https://api.example.com/y"
    )
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = auth_response.url.split("code=")[1].split("&")[0]

    # Step 2: Token request WITHOUT resource parameter
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            # No resource parameter - should get all authorized resources
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()

    # Verify token has all authorized resources

    access_token = AccessToken.objects.get(token=token_data["access_token"])
    token_resources = access_token.resource
    assert set(token_resources) == {
        "https://api.example.com/x",
        "https://api.example.com/y",
    }


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_refresh_token_preserves_resource(client, oauth2_settings):
    """
    Test that resource restrictions are preserved through refresh token flow.

    The grant is deleted after initial token issuance, so the RefreshToken
    must carry the resource information for subsequent refresh operations.
    """

    User = get_user_model()
    Application = get_application_model()

    # Setup
    user = User.objects.create_user("refresh_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-refresh"

    app = Application.objects.create(
        name="Refresh Test Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization with resource
    auth_url = reverse("oauth2_provider:authorize")
    from urllib.parse import urlencode

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read write",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/protected"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = auth_response.url.split("code=")[1].split("&")[0]

    # Step 2: Exchange code for tokens
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()

    # Verify initial access token has resource
    access_token_1 = AccessToken.objects.get(token=token_data["access_token"])
    assert access_token_1.resource == ["https://api.example.com/protected"]

    # Verify refresh token has resource stored
    refresh_token = RefreshToken.objects.get(token=token_data["refresh_token"])
    assert refresh_token.resource == ["https://api.example.com/protected"]

    # Verify grant is deleted (DOT behavior)
    assert Grant.objects.filter(code=code).count() == 0

    # Step 3: Use refresh token to get new access token
    refresh_response = client.post(
        token_url,
        {
            "grant_type": "refresh_token",
            "refresh_token": token_data["refresh_token"],
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )

    assert refresh_response.status_code == 200
    refresh_data = refresh_response.json()

    # Step 4: Verify new access token preserves resource from refresh token
    access_token_2 = AccessToken.objects.get(token=refresh_data["access_token"])
    assert access_token_2.resource == ["https://api.example.com/protected"]
    assert access_token_2.allows_audience("https://api.example.com/protected") is True
    assert access_token_2.allows_audience("https://other.example.com") is False


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_refresh_token_rejects_unauthorized_resource(client, oauth2_settings):
    """
    Test refresh token resource validation: rejects unauthorized resources, allows narrowing.

    RFC 8707 security: Prevents resource escalation during refresh while allowing
    clients to narrow to a subset of originally authorized resources.
    """

    User = get_user_model()
    Application = get_application_model()

    # Setup
    user = User.objects.create_user("subset_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-subset"

    app = Application.objects.create(
        name="Subset Test Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization with specific resources
    auth_url = reverse("oauth2_provider:authorize")
    from urllib.parse import urlencode

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read write",
    }
    # Request authorization for two specific resources
    query_string = (
        urlencode(params)
        + "&resource=https://api.example.com/resource1"
        + "&resource=https://api.example.com/resource2"
    )
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = auth_response.url.split("code=")[1].split("&")[0]

    # Step 2: Exchange code for tokens
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()

    # Verify refresh token has both resources
    refresh_token = RefreshToken.objects.get(token=token_data["refresh_token"])
    assert set(refresh_token.resource) == {
        "https://api.example.com/resource1",
        "https://api.example.com/resource2",
    }

    # Step 3: Attempt refresh with unauthorized resource - should fail
    refresh_response_invalid = client.post(
        token_url,
        {
            "grant_type": "refresh_token",
            "refresh_token": token_data["refresh_token"],
            "resource": "https://api.example.com/resource3",  # Not in original set
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )

    assert refresh_response_invalid.status_code == 400
    error_data = json.loads(refresh_response_invalid.content)
    assert error_data["error"] == "invalid_target"
    assert "resource3" in error_data["error_description"]

    # Step 4: Get fresh token to test narrowing (previous refresh may have consumed token)
    auth_response2 = client.get(f"{auth_url}?{query_string}")
    assert auth_response2.status_code == 302
    code2 = auth_response2.url.split("code=")[1].split("&")[0]

    token_response2 = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code2,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )
    assert token_response2.status_code == 200
    token_data2 = token_response2.json()

    # Step 5: Refresh with subset (resource1 only) - should succeed
    refresh_response_subset = client.post(
        token_url,
        {
            "grant_type": "refresh_token",
            "refresh_token": token_data2["refresh_token"],
            "resource": "https://api.example.com/resource1",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )

    assert refresh_response_subset.status_code == 200
    subset_data = refresh_response_subset.json()
    subset_access_token = AccessToken.objects.get(token=subset_data["access_token"])
    # New token should have only the requested subset
    assert subset_access_token.resource == ["https://api.example.com/resource1"]


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False, "ROTATE_REFRESH_TOKEN": True})
def test_rfc8707_refresh_token_rotation_preserves_resource(client, oauth2_settings):
    """
    Test that resource is preserved when refresh tokens are rotated.

    When ROTATE_REFRESH_TOKEN is enabled, the new refresh token must carry
    the same resource restrictions as the original.
    """

    User = get_user_model()
    Application = get_application_model()

    # Setup
    user = User.objects.create_user("rotation_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-rotation"

    app = Application.objects.create(
        name="Rotation Test Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization with resource
    auth_url = reverse("oauth2_provider:authorize")
    from urllib.parse import urlencode

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read write",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/protected"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = auth_response.url.split("code=")[1].split("&")[0]

    # Step 2: Exchange code for tokens
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()
    original_refresh_token = token_data["refresh_token"]

    # Verify original refresh token has resource
    refresh_token_1 = RefreshToken.objects.get(token=original_refresh_token)
    assert refresh_token_1.resource == ["https://api.example.com/protected"]

    # Step 3: Use refresh token (should rotate and create new refresh token)
    refresh_response = client.post(
        token_url,
        {
            "grant_type": "refresh_token",
            "refresh_token": original_refresh_token,
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
        },
    )

    assert refresh_response.status_code == 200
    refresh_data = refresh_response.json()

    # Verify new access token has resource
    access_token_2 = AccessToken.objects.get(token=refresh_data["access_token"])
    assert access_token_2.resource == ["https://api.example.com/protected"]

    # Verify new refresh token was issued (rotation)
    new_refresh_token = refresh_data["refresh_token"]
    assert new_refresh_token != original_refresh_token

    # Verify new refresh token also has resource preserved
    refresh_token_2 = RefreshToken.objects.get(token=new_refresh_token)
    assert refresh_token_2.resource == ["https://api.example.com/protected"]
