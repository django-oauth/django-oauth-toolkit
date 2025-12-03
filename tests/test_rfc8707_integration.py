import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse


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
    from oauth2_provider.models import AccessToken, Grant, get_application_model

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
    # RFC 8707: Multiple resource parameters sent as repeated query parameters
    # Note: Django test client doesn't support multiple values in dict syntax
    # so we pass the full URL with query string
    from urllib.parse import urlencode

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

    # Verify grant has resource stored (JSON array format)
    grant = Grant.objects.get(code=code)
    import json

    grant_resources = json.loads(grant.resource)
    assert grant_resources == ["https://api.example.com/mcp", "https://data.example.com/mcp"]

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
    token_resources = json.loads(access_token.resource)
    assert token_resources == ["https://api.example.com/mcp"]

    # Step 4: Verify audience validation
    assert access_token.allows_audience("https://api.example.com/mcp") is True
    assert access_token.allows_audience("https://data.example.com/mcp") is False
    assert access_token.allows_audience("https://evil.example.com") is False

    # Verify audience list
    audiences = access_token.get_audiences()
    assert audiences == ["https://api.example.com/mcp"]


@pytest.mark.django_db
def test_rfc8707_client_credentials_flow_with_resource(client):
    """
    Integration test for RFC 8707 with client credentials grant.
    """
    from oauth2_provider.models import AccessToken, get_application_model

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
    import json

    token_resources = json.loads(access_token.resource)
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
    from oauth2_provider.models import AccessToken, get_application_model

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
    from urllib.parse import parse_qs, urlencode, urlparse

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
    import json

    access_token = AccessToken.objects.get(token=access_token_value)
    token_resources = json.loads(access_token.resource)
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
    from oauth2_provider.models import get_application_model

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
    assert "was not included in the original authorization grant" in error_data["error_description"]


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_request_with_single_resource_from_multiple(client, oauth2_settings):
    """
    Test that token request can specify a single resource from multiple authorized resources.

    Note: oauthlib limitation prevents sending multiple resource values in POST requests,
    so we only test single resource narrowing here.
    """
    from oauth2_provider.models import AccessToken, get_application_model

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("subset_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-abc"

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

    # Step 1: Authorization with 3 resources
    auth_url = reverse("oauth2_provider:authorize")
    from urllib.parse import urlencode

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = (
        urlencode(params)
        + "&resource=https://api.example.com/a"
        + "&resource=https://api.example.com/b"
        + "&resource=https://api.example.com/c"
    )
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = auth_response.url.split("code=")[1].split("&")[0]

    # Step 2: Token request with 1 of the 3 resources (valid subset)
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "resource": "https://api.example.com/b",  # Select middle resource
        },
    )

    assert token_response.status_code == 200
    token_data = token_response.json()

    # Verify token has only the requested resource
    import json as json_lib

    access_token = AccessToken.objects.get(token=token_data["access_token"])
    token_resources = json_lib.loads(access_token.resource)
    assert token_resources == ["https://api.example.com/b"]


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_request_without_resource_gets_all(client, oauth2_settings):
    """
    Test that token request without resource parameter gets all authorized resources.
    """
    from oauth2_provider.models import AccessToken, get_application_model

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
    from urllib.parse import urlencode

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
    import json as json_lib

    access_token = AccessToken.objects.get(token=token_data["access_token"])
    token_resources = json_lib.loads(access_token.resource)
    assert set(token_resources) == {"https://api.example.com/x", "https://api.example.com/y"}


@pytest.mark.django_db
@pytest.mark.oauth2_settings({"PKCE_REQUIRED": False})
def test_rfc8707_token_request_different_resource_rejected(client, oauth2_settings):
    """
    Test that token request is rejected if it requests a resource not in the authorization,
    even if other resources were authorized.
    """
    from oauth2_provider.models import get_application_model

    User = get_user_model()
    Application = get_application_model()

    user = User.objects.create_user("different_user", "test@example.com", "123456")
    plaintext_secret = "test-secret-ghi"

    app = Application.objects.create(
        name="Different Resource Client",
        user=user,
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        skip_authorization=True,
        client_secret=plaintext_secret,
    )

    client.force_login(user)

    # Step 1: Authorization with 2 resources (p and q)
    auth_url = reverse("oauth2_provider:authorize")
    from urllib.parse import urlencode

    params = {
        "client_id": app.client_id,
        "response_type": "code",
        "redirect_uri": "https://client.example.com/callback",
        "scope": "read",
    }
    query_string = (
        urlencode(params) + "&resource=https://api.example.com/p&resource=https://api.example.com/q"
    )
    auth_response = client.get(f"{auth_url}?{query_string}")

    assert auth_response.status_code == 302
    code = auth_response.url.split("code=")[1].split("&")[0]

    # Step 2: Token request with a different resource (r - not authorized!)
    token_url = reverse("oauth2_provider:token")
    token_response = client.post(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/callback",
            "client_id": app.client_id,
            "client_secret": plaintext_secret,
            "resource": "https://api.example.com/r",  # NOT in {p, q}
        },
    )

    # Should be rejected because the resource was not authorized
    assert token_response.status_code == 400

    import json as json_lib

    error_data = json_lib.loads(token_response.content)
    assert error_data["error"] == "invalid_target"
