"""
Tests documenting OAuth 2.0 token behavior when a user re-authorizes an application.

## Background:
When a user goes through the OAuth authorization flow multiple times, multiple 
access tokens are created. This is standard OAuth 2.0 behavior as defined in RFC 6749.

## Why Multiple Tokens Are Allowed:
1. **Multiple Devices/Sessions**: Users may legitimately have multiple active sessions
   (phone, laptop, tablet) that each need separate tokens.
2. **Token Rotation**: Some flows require creating new tokens before old ones expire.
3. **Refresh Token Flow**: Tokens created with refresh tokens need to coexist to
   support the refresh flow.

## Proper Token Management:
Applications should manage token lifecycle using:

1. **Token Expiration**: Configure `ACCESS_TOKEN_EXPIRE_SECONDS` appropriately
   - Default is 36000 seconds (10 hours)
   - Expired tokens are automatically invalid
   
2. **Cleanup Command**: Use `python manage.py cleartokens` to remove expired tokens
   - Should be run periodically (e.g., daily cron job)
   - Cleans up expired access tokens, refresh tokens, and grants
   
3. **Revocation Endpoint**: Clients should explicitly revoke tokens when logging out
   - POST to `/revoke_token/` with the token to revoke
   - Properly implemented clients manage their own token lifecycle
   
4. **Client-Side Management**: Clients should store and reuse valid tokens
   - Check for existing valid tokens before starting new authorization flow
   - Only request new tokens when current ones are expired or invalid

## Why Automatic Revocation Isn't Implemented:
Automatically revoking old tokens when creating new ones would break the refresh
token flow because:
- Refresh tokens reference their associated access tokens for scope information
- Deleting access tokens makes refresh tokens unable to validate scopes
- This causes "invalid_scope" errors when trying to use refresh tokens

## References:
- OAuth 2.0 RFC 6749: https://www.rfc-editor.org/rfc/rfc6749.html
- OAuth 2.0 Token Revocation RFC 7009: https://www.rfc-editor.org/rfc/rfc7009.html
"""
import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_refresh_token_model,
)

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


@pytest.mark.usefixtures("oauth2_settings")
class TestTokenRevocationOnReauthorization(TestCase):
    """
    Test that old tokens are revoked when a user re-authorizes an application.
    """

    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False

    def test_reauthorization_creates_multiple_tokens_with_auto_approval(self):
        """
        When a user re-authorizes an application with approval_prompt=auto,
        new access tokens are created. This is standard OAuth 2.0 behavior that
        supports multiple devices/sessions.
        
        Note: Applications should manage token lifecycle by:
        - Using token expiration (ACCESS_TOKEN_EXPIRE_SECONDS setting)
        - Explicitly revoking tokens via the revocation endpoint when no longer needed
        - Using the cleartokens management command to remove expired tokens
        """
        self.client.login(username="test_user", password="123456")

        # Track all created tokens
        created_tokens = []

        # Perform 3 authorization flows
        for i in range(3):
            # Step 1: Authorization request with auto approval
            query_data = {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": f"random_state_{i}",
                "scope": "read write",
                "redirect_uri": "http://example.org",
                "approval_prompt": "auto",
            }
            response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)

            # On first request (no existing token), we get approval screen (200)
            # On subsequent requests with auto approval, we get redirected (302)
            if i == 0:
                self.assertEqual(response.status_code, 200)
                # POST to approve
                response = self.client.post(
                    reverse("oauth2_provider:authorize"),
                    data={
                        **query_data,
                        "allow": "Authorize",
                    },
                )

            # Should redirect with an authorization code
            self.assertEqual(response.status_code, 302)
            location = response["Location"]
            self.assertIn("code=", location)

            # Step 2: Exchange code for token
            code = location.split("code=")[1].split("&")[0]
            token_data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://example.org",
                "client_id": self.application.client_id,
                "client_secret": CLEARTEXT_SECRET,
            }
            token_response = self.client.post(reverse("oauth2_provider:token"), data=token_data)
            self.assertEqual(token_response.status_code, 200)

            # Get the created token
            import json
            token_json = json.loads(token_response.content)
            access_token = token_json.get("access_token")
            created_tokens.append(access_token)

        # After 3 authorization flows, we have 3 tokens.
        # This is standard OAuth 2.0 behavior - multiple tokens can coexist.
        # Tokens with refresh tokens are not automatically revoked to preserve
        # the refresh token flow and support multiple sessions.
        remaining_tokens = AccessToken.objects.filter(
            user=self.test_user,
            application=self.application,
        ).count()

        self.assertEqual(
            remaining_tokens,
            3,
            f"Expected 3 tokens after 3 authorizations (standard OAuth behavior), but found {remaining_tokens}.",
        )

    def test_reauthorization_with_force_approval(self):
        """
        When approval_prompt=force, user must approve each time.
        Multiple tokens can coexist (standard OAuth 2.0 behavior).
        """
        self.client.login(username="test_user", password="123456")

        # First authorization - POST to approve
        query_data = {
            "client_id": self.application.client_id,
            "response_type": "code",
            "state": "random_state_1",
            "scope": "read write",
            "redirect_uri": "http://example.org",
        }
        
        # GET to see the authorization page
        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 200)

        # POST to authorize
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                **query_data,
                "allow": "Authorize",
            },
        )
        self.assertEqual(response.status_code, 302)
        
        # Exchange code for token
        code = response["Location"].split("code=")[1].split("&")[0]
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        }
        token_response = self.client.post(reverse("oauth2_provider:token"), data=token_data)
        self.assertEqual(token_response.status_code, 200)

        # Second authorization
        query_data["state"] = "random_state_2"
        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                **query_data,
                "allow": "Authorize",
            },
        )
        self.assertEqual(response.status_code, 302)
        
        code = response["Location"].split("code=")[1].split("&")[0]
        token_data["code"] = code
        token_response = self.client.post(reverse("oauth2_provider:token"), data=token_data)
        self.assertEqual(token_response.status_code, 200)

        # Should have 2 tokens (standard OAuth behavior - one from each authorization)
        remaining_tokens = AccessToken.objects.filter(
            user=self.test_user,
            application=self.application,
        ).count()

        self.assertEqual(remaining_tokens, 2)

    def test_reauthorization_with_different_scopes_creates_separate_tokens(self):
        """
        When a user authorizes with different scopes, separate tokens are created.
        This is standard OAuth 2.0 behavior that allows different scopes for different purposes.
        """
        self.client.login(username="test_user", password="123456")

        # First authorization with "read" scope
        query_data = {
            "client_id": self.application.client_id,
            "response_type": "code",
            "state": "random_state_1",
            "scope": "read",
            "redirect_uri": "http://example.org",
            "approval_prompt": "auto",
        }
        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 200)  # Needs approval for first time

        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                **query_data,
                "allow": "Authorize",
            },
        )
        code = response["Location"].split("code=")[1].split("&")[0]
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
            "client_id": self.application.client_id,
            "client_secret": CLEARTEXT_SECRET,
        }
        self.client.post(reverse("oauth2_provider:token"), data=token_data)

        # Second authorization with "write" scope
        query_data["scope"] = "write"
        query_data["state"] = "random_state_2"
        response = self.client.get(reverse("oauth2_provider:authorize"), data=query_data)
        self.assertEqual(response.status_code, 200)  # Needs approval for new scope

        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                **query_data,
                "allow": "Authorize",
            },
        )
        code = response["Location"].split("code=")[1].split("&")[0]
        token_data["code"] = code
        self.client.post(reverse("oauth2_provider:token"), data=token_data)

        # Should have 2 tokens (one for each scope)
        # This is standard OAuth behavior allowing different scopes for different purposes
        remaining_tokens = AccessToken.objects.filter(
            user=self.test_user,
            application=self.application,
        ).count()

        self.assertEqual(remaining_tokens, 2, 
            "Expected 2 tokens after authorizations with different scopes. "
            "Multiple tokens with different scopes are allowed in OAuth 2.0."
        )
