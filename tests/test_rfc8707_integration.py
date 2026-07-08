import json
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

from oauth2_provider.models import AccessToken, Grant, RefreshToken, get_application_model


@pytest.mark.django_db(databases="__all__")
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
    code = parse_qs(urlparse(redirect_url).query)["code"][0]

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


@pytest.mark.django_db(databases="__all__")
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


@pytest.mark.django_db(databases="__all__")
def test_rfc8707_rejects_invalid_resource_uri(client):
    """
    Token request with a malformed resource URI is rejected with invalid_target.
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("invalid_uri_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-invalid"

    app = Application.objects.create(
        name="Invalid URI Test Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
        client_secret=plaintext_secret,
    )

    token_url = reverse("oauth2_provider:token")

    # Relative URI (not absolute)
    response = client.post(
        token_url,
        {
            "grant_type": "client_credentials",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "resource": "/not/absolute",
        },
    )
    assert response.status_code == 400
    error_data = json.loads(response.content)
    assert error_data["error"] == "invalid_target"

    # URI with userinfo
    response = client.post(
        token_url,
        {
            "grant_type": "client_credentials",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "resource": "https://user:pass@api.example.com/v1",
        },
    )
    assert response.status_code == 400
    error_data = json.loads(response.content)
    assert error_data["error"] == "invalid_target"


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_authorization_endpoint_rejects_invalid_resource_uri(client, oauth2_settings):
    """
    Authorization request with a malformed resource URI is rejected with an
    invalid_target error redirect, before anything is stored on a grant.
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("authz_invalid_user", "test@example.com", "123456")
    app = Application.objects.create(
        name="Authz Invalid Resource Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret="test-secret-authz-invalid",
    )

    client.force_login(user)

    auth_url = reverse("oauth2_provider:authorize")
    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
        "state": "csrf_protection_state",
    }
    query_string = urlencode(params) + "&resource=/not/absolute"
    response = client.get(f"{auth_url}?{query_string}")

    # invalid_target is a redirect-style error per RFC 6749 section 4.1.2.1,
    # and the redirect must echo the client's state
    assert response.status_code == 302
    assert "error=invalid_target" in response.url
    assert "state=csrf_protection_state" in response.url
    assert Grant.objects.count() == 0


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_issuance_validates_inherited_grant_resource(client, oauth2_settings):
    """
    Malformed resource values on a stored grant (e.g. rows written before the
    authorization endpoint validated them) must not flow onto issued tokens.
    """
    import datetime

    from django.utils import timezone

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("grant_invalid_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-grant-invalid"
    app = Application.objects.create(
        name="Grant Invalid Resource Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    # Simulate a legacy grant row carrying an unvalidated resource value
    grant = Grant.objects.create(
        user=user,
        application=app,
        code="legacy_grant_code",
        expires=timezone.now() + datetime.timedelta(minutes=5),
        redirect_uri="https://client.example.com/callback",
        scope="read",
        resource=["/not/absolute"],
    )

    token_url = reverse("oauth2_provider:token")
    response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": grant.code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            # No resource parameter: the grant's resources would be inherited
        },
    )

    assert response.status_code == 400
    error_data = json.loads(response.content)
    assert error_data["error"] == "invalid_target"


@pytest.mark.django_db(databases="__all__")
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


@pytest.mark.django_db(databases="__all__")
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

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/safe"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

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
    error_data = json.loads(token_response.content)
    assert error_data["error"] == "invalid_target"
    assert (
        "cannot escalate resource permissions beyond the original authorization grant"
        in error_data["error_description"]
    )


@pytest.mark.django_db(databases="__all__")
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
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

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


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_request_with_repeated_resource_params(client, oauth2_settings):
    """
    Test that the token endpoint accepts multiple repeated resource parameters.

    RFC 8707 conveys multiple resources by repeating the parameter, in the
    token request as well as the authorization request.
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("multi_token_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-multi"

    app = Application.objects.create(
        name="Multi Resource Token Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization with three resources
    auth_url = reverse("oauth2_provider:authorize")
    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = (
        urlencode(params)
        + "&resource=https://api.example.com/x"
        + "&resource=https://api.example.com/y"
        + "&resource=https://api.example.com/z"
    )
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

    # Step 2: Token request repeating the resource parameter to narrow to two
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            # Django's test client encodes a list as repeated parameters
            "resource": ["https://api.example.com/x", "https://api.example.com/y"],
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()

    access_token = AccessToken.objects.get(token=token_data["access_token"])
    assert set(access_token.resource) == {
        "https://api.example.com/x",
        "https://api.example.com/y",
    }


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_request_repeated_resource_params_reject_escalation(client, oauth2_settings):
    """
    Test that repeated resource parameters cannot escalate beyond the grant.

    If any of the repeated resource values was not authorized in the grant,
    the token request must fail with invalid_target.
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("multi_escalation_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-multi-esc"

    app = Application.objects.create(
        name="Multi Resource Escalation Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization with a single resource
    auth_url = reverse("oauth2_provider:authorize")
    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/x"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

    # Step 2: Token request repeating resource params, one outside the grant
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "resource": ["https://api.example.com/x", "https://api.example.com/unauthorized"],
        },
    )

    assert token_response.status_code == 400

    # Parse the JSON response (Note: Content-Type may be incorrect due to oauthlib CustomOAuth2Error)
    error_data = json.loads(token_response.content)
    assert error_data["error"] == "invalid_target"


@pytest.mark.django_db(databases="__all__")
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

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read write",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/protected"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

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


@pytest.mark.django_db(databases="__all__")
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
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

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
    code2 = parse_qs(urlparse(auth_response2.url).query)["code"][0]

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


@pytest.mark.django_db(databases="__all__")
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

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read write",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/protected"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

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


@pytest.mark.django_db(databases="__all__")
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False, "ROTATE_REFRESH_TOKEN": False})
def test_rfc8707_non_rotating_refresh_preserves_resource(client, oauth2_settings):
    """
    Test that resource is preserved on the reused access token when
    ROTATE_REFRESH_TOKEN is False (non-rotating refresh path).
    """

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("nonrotate_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-nonrotate"

    app = Application.objects.create(
        name="Non-Rotate Test Client",
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
    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read write",
    }
    query_string = urlencode(params) + "&resource=https://api.example.com/protected"
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = parse_qs(urlparse(auth_response.url).query)["code"][0]

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

    # Step 3: Refresh (non-rotating — same refresh token reused, access token updated in place)
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

    # Same refresh token should be returned
    assert refresh_data["refresh_token"] == original_refresh_token

    # Verify the updated access token preserves resource
    access_token = AccessToken.objects.get(token=refresh_data["access_token"])
    assert access_token.resource == ["https://api.example.com/protected"]
