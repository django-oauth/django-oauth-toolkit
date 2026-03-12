import datetime
import hashlib

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from oauth2_provider.middleware import OAuth2ExtraTokenMiddleware
from oauth2_provider.models import get_access_token_model, get_application_model


Application = get_application_model()
AccessToken = get_access_token_model()
User = get_user_model()


class TestOAuth2ExtraTokenMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = OAuth2ExtraTokenMiddleware(lambda r: None)

        # Create test user and application for valid token tests
        self.user = User.objects.create_user("test_user", "test@example.com", "123456")
        self.application = Application.objects.create(
            name="Test Application",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

    def test_malformed_bearer_header_no_token(self):
        """Test that 'Authorization: Bearer' without token doesn't crash"""
        request = self.factory.get("/", HTTP_AUTHORIZATION="Bearer")

        # This should not raise an IndexError
        _ = self.middleware(request)

        # Should not have access_token attribute
        self.assertFalse(hasattr(request, "access_token"))

    def test_malformed_bearer_header_empty_token(self):
        """Test that 'Authorization: Bearer ' with empty token doesn't crash"""
        request = self.factory.get("/", HTTP_AUTHORIZATION="Bearer ")

        # This should not raise an IndexError
        _ = self.middleware(request)

        # Should not have access_token attribute
        self.assertFalse(hasattr(request, "access_token"))

    def test_valid_bearer_token(self):
        """Test that valid bearer token works correctly"""
        # Create a valid access token
        token_string = "test-token-12345"
        token_checksum = hashlib.sha256(token_string.encode("utf-8")).hexdigest()
        access_token = AccessToken.objects.create(
            user=self.user,
            scope="read",
            expires=datetime.datetime.now() + datetime.timedelta(days=1),
            token=token_string,
            token_checksum=token_checksum,
            application=self.application,
        )

        request = self.factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token_string}")

        _ = self.middleware(request)

        # Should have access_token attribute set
        self.assertTrue(hasattr(request, "access_token"))
        self.assertEqual(request.access_token, access_token)

    def test_invalid_bearer_token(self):
        """Test that invalid bearer token doesn't crash but doesn't set access_token"""
        request = self.factory.get("/", HTTP_AUTHORIZATION="Bearer invalid-token-xyz")

        # This should not raise an exception
        _ = self.middleware(request)

        # Should not have access_token attribute
        self.assertFalse(hasattr(request, "access_token"))

    def test_no_authorization_header(self):
        """Test that request without Authorization header works normally"""
        request = self.factory.get("/")

        _ = self.middleware(request)

        # Should not have access_token attribute
        self.assertFalse(hasattr(request, "access_token"))

    def test_non_bearer_authorization_header(self):
        """Test that non-Bearer authorization headers are ignored"""
        request = self.factory.get("/", HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz")

        _ = self.middleware(request)

        # Should not have access_token attribute
        self.assertFalse(hasattr(request, "access_token"))
