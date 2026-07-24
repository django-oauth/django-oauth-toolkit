import logging

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory
from django.views.generic import View
from oauthlib.oauth2 import Server

from oauth2_provider.oauth2_backends import OAuthLibCore
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.views.mixins import (
    OAuthLibMixin,
    OIDCLogoutOnlyMixin,
    OIDCOnlyMixin,
    ProtectedResourceMetadataMixin,
    ProtectedResourceMixin,
    ReadWriteScopedResourceMixin,
    ScopedResourceMixin,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


@pytest.mark.usefixtures("oauth2_settings")
class BaseTest(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request_factory = RequestFactory()
        super().setUpClass()


class TestOAuthLibMixin(BaseTest):
    def test_missing_oauthlib_backend_class_uses_fallback(self):
        class CustomOauthLibBackend:
            def __init__(self, *args, **kwargs):
                pass

        self.oauth2_settings.OAUTH2_BACKEND_CLASS = CustomOauthLibBackend

        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        test_view = TestView()

        self.assertEqual(CustomOauthLibBackend, test_view.get_oauthlib_backend_class())
        core = test_view.get_oauthlib_core()
        self.assertTrue(isinstance(core, CustomOauthLibBackend))

    def test_missing_server_class_uses_fallback(self):
        class CustomServer:
            def __init__(self, *args, **kwargs):
                pass

        self.oauth2_settings.OAUTH2_SERVER_CLASS = CustomServer

        class TestView(OAuthLibMixin, View):
            validator_class = OAuth2Validator
            oauthlib_backend_class = OAuthLibCore

        test_view = TestView()

        self.assertEqual(CustomServer, test_view.get_server_class())
        core = test_view.get_oauthlib_core()
        self.assertTrue(isinstance(core.server, CustomServer))

    def test_missing_validator_class_uses_fallback(self):
        class CustomValidator:
            pass

        self.oauth2_settings.OAUTH2_VALIDATOR_CLASS = CustomValidator

        class TestView(OAuthLibMixin, View):
            server_class = Server
            oauthlib_backend_class = OAuthLibCore

        test_view = TestView()

        self.assertEqual(CustomValidator, test_view.get_validator_class())
        core = test_view.get_oauthlib_core()
        self.assertTrue(isinstance(core.server.request_validator, CustomValidator))

    def test_correct_server(self):
        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator
            oauthlib_backend_class = OAuthLibCore

        request = self.request_factory.get("/fake-req")
        request.user = "fake"
        test_view = TestView()

        self.assertIsInstance(test_view.get_server(), Server)

    def test_custom_backend(self):
        class AnotherOauthLibBackend:
            pass

        class TestView(OAuthLibMixin, View):
            server_class = Server
            validator_class = OAuth2Validator
            oauthlib_backend_class = AnotherOauthLibBackend

        request = self.request_factory.get("/fake-req")
        request.user = "fake"
        test_view = TestView()

        self.assertEqual(test_view.get_oauthlib_backend_class(), AnotherOauthLibBackend)


class TestScopedResourceMixin(BaseTest):
    def test_missing_required_scopes(self):
        class TestView(ScopedResourceMixin, View):
            pass

        test_view = TestView()

        self.assertRaises(ImproperlyConfigured, test_view.get_scopes)

    def test_correct_required_scopes(self):
        class TestView(ScopedResourceMixin, View):
            required_scopes = ["scope1", "scope2"]

        test_view = TestView()

        self.assertEqual(test_view.get_scopes(), ["scope1", "scope2"])


class TestReadWriteScopedResourceMixin(BaseTest):
    """
    Regression tests for
    https://github.com/django-oauth/django-oauth-toolkit/issues/694
    """

    def test_instantiation_with_no_arguments_still_works(self):
        class TestView(ReadWriteScopedResourceMixin, View):
            required_scopes = ["read"]

        TestView()  # Just checking no crash.

    def test_instantiation_with_keyword_arguments(self):
        """
        __new__() must not forward extra keyword arguments down to
        object.__new__(). Because the mixin overrides __new__(),
        object.__new__() rejects any extra argument outright, so
        forwarding them broke instantiation with any argument at all
        for classes mixing this in (notably Django REST Framework's
        cls(**initkwargs) view instantiation, which Django's own
        View.as_view() also uses), raising "object.__new__() takes
        exactly one argument" instead of constructing the instance
        normally.
        """

        class TestView(ReadWriteScopedResourceMixin, View):
            required_scopes = ["read"]

        TestView(some_kwarg="value")  # Just checking no crash.

    def test_instantiation_with_positional_and_keyword_arguments(self):
        """
        The originally reported reproduction (issue #694) instantiated
        a subclass defining its own ``__init__(self, *args, **kwargs)``
        with *both* a positional and a keyword argument. Django's
        ``View.__init__`` does not accept positional arguments, so cover
        that case directly with a view that does, ensuring ``__new__()``
        forwards nothing to ``object.__new__()``.
        """

        class TestView(ReadWriteScopedResourceMixin, View):
            required_scopes = ["read"]

            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                super().__init__()

        test_view = TestView(True, some_kwarg="value")  # Just checking no crash.
        self.assertEqual(test_view.args, (True,))
        self.assertEqual(test_view.kwargs, {"some_kwarg": "value"})


class TestProtectedResourceMixin(BaseTest):
    def test_options_shall_pass(self):
        class TestView(ProtectedResourceMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        request = self.request_factory.options("/fake-req")
        view = TestView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 200)

    def test_denied_returns_bare_403_by_default(self):
        """Regression guard: the default mixin still returns a plain 403 (no challenge)."""

        class TestView(ProtectedResourceMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        request = self.request_factory.get("/fake-req")
        response = TestView.as_view()(request)
        self.assertEqual(response.status_code, 403)
        assert "WWW-Authenticate" not in response


class TestProtectedResourceMetadataMixin(BaseTest):
    def test_denied_returns_401_with_resource_metadata_challenge(self):
        class TestView(ProtectedResourceMetadataMixin, ProtectedResourceMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        request = self.request_factory.get("/fake-req")
        response = TestView.as_view()(request)
        self.assertEqual(response.status_code, 401)
        challenge = response["WWW-Authenticate"]
        assert challenge.startswith("Bearer")
        assert 'resource_metadata="http://testserver/o/.well-known/oauth-protected-resource"' in challenge

    def test_realm_is_advertised_when_set(self):
        class TestView(ProtectedResourceMetadataMixin, ProtectedResourceMixin, View):
            server_class = Server
            validator_class = OAuth2Validator
            www_authenticate_realm = "example"

        request = self.request_factory.get("/fake-req")
        response = TestView.as_view()(request)
        self.assertEqual(response.status_code, 401)
        assert 'realm="example"' in response["WWW-Authenticate"]

    def test_resource_metadata_url_override_is_advertised(self):
        """A path-based/multi-tenant view can advertise its own metadata URL."""
        url = "https://api.example.com/.well-known/oauth-protected-resource/tenant1"

        class TestView(ProtectedResourceMetadataMixin, ProtectedResourceMixin, View):
            server_class = Server
            validator_class = OAuth2Validator
            resource_metadata_url = url

        request = self.request_factory.get("/fake-req")
        response = TestView.as_view()(request)
        self.assertEqual(response.status_code, 401)
        assert 'resource_metadata="{}"'.format(url) in response["WWW-Authenticate"]

    def test_insufficient_scope_yields_403(self):
        """RFC 6750: a valid token with insufficient scope is a 403, still with a challenge."""

        class TestView(ProtectedResourceMetadataMixin, ProtectedResourceMixin, View):
            server_class = Server
            validator_class = OAuth2Validator

        class FakeOauthlibRequest:
            oauth2_error = {"error": "insufficient_scope", "error_description": "nope"}

        request = self.request_factory.get("/fake-req")
        response = TestView().unauthenticated_response(request, FakeOauthlibRequest())
        self.assertEqual(response.status_code, 403)
        assert response["WWW-Authenticate"].startswith("Bearer")
        assert 'error="insufficient_scope"' in response["WWW-Authenticate"]


@pytest.fixture
def oidc_only_view():
    class TView(OIDCOnlyMixin, View):
        def get(self, *args, **kwargs):
            return HttpResponse("OK")

    return TView.as_view()


@pytest.fixture
def oidc_logout_only_view():
    class TView(OIDCLogoutOnlyMixin, View):
        def get(self, *args, **kwargs):
            return HttpResponse("OK")

    return TView.as_view()


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_oidc_only_mixin_oidc_enabled(oauth2_settings, rf, oidc_only_view):
    assert oauth2_settings.OIDC_ENABLED
    rsp = oidc_only_view(rf.get("/"))
    assert rsp.status_code == 200
    assert rsp.content.decode("utf-8") == "OK"


@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RP_LOGOUT)
def test_oidc_logout_only_mixin_oidc_enabled(oauth2_settings, rf, oidc_only_view):
    assert oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED
    rsp = oidc_only_view(rf.get("/"))
    assert rsp.status_code == 200
    assert rsp.content.decode("utf-8") == "OK"


def test_oidc_only_mixin_oidc_disabled_debug(oauth2_settings, rf, settings, oidc_only_view):
    assert oauth2_settings.OIDC_ENABLED is False
    settings.DEBUG = True
    with pytest.raises(ImproperlyConfigured) as exc:
        oidc_only_view(rf.get("/"))
    assert "OIDC views are not enabled" in str(exc.value)


def test_oidc_logout_only_mixin_oidc_disabled_debug(oauth2_settings, rf, settings, oidc_logout_only_view):
    assert oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED is False
    settings.DEBUG = True
    with pytest.raises(ImproperlyConfigured) as exc:
        oidc_logout_only_view(rf.get("/"))
        assert str(exc.value) == OIDCLogoutOnlyMixin.debug_error_message


def test_oidc_only_mixin_oidc_disabled_no_debug(oauth2_settings, rf, settings, oidc_only_view, caplog):
    assert oauth2_settings.OIDC_ENABLED is False
    settings.DEBUG = False
    with caplog.at_level(logging.WARNING, logger="oauth2_provider"):
        rsp = oidc_only_view(rf.get("/"))
    assert rsp.status_code == 404
    assert len(caplog.records) == 1
    assert "OIDC views are not enabled" in caplog.records[0].message


def test_oidc_logout_only_mixin_oidc_disabled_no_debug(
    oauth2_settings, rf, settings, oidc_logout_only_view, caplog
):
    assert oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED is False
    settings.DEBUG = False
    with caplog.at_level(logging.WARNING, logger="oauth2_provider"):
        rsp = oidc_logout_only_view(rf.get("/"))
        assert rsp.status_code == 404
        assert len(caplog.records) == 1
        assert caplog.records[0].message == OIDCLogoutOnlyMixin.debug_error_message
