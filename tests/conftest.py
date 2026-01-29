import uuid
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from django import VERSION
from django.conf import settings as test_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import dateformat, timezone
from jwcrypto import jwk, jwt

from oauth2_provider.models import get_application_model, get_id_token_model
from oauth2_provider.settings import oauth2_settings as _oauth2_settings

from . import presets


Application = get_application_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


class OAuthSettingsWrapper:
    """
    A wrapper around oauth2_settings to ensure that when an overridden value is
    set, it also records it in _cached_attrs, so that the settings can be reset.
    """

    def __init__(self, settings, user_settings):
        self.settings = settings
        if not user_settings:
            user_settings = {}
        self.update(user_settings)

    def update(self, user_settings):
        self.settings.OAUTH2_PROVIDER = user_settings
        _oauth2_settings.reload()
        # Reload OAuthlibCore for every view request during tests
        self.ALWAYS_RELOAD_OAUTHLIB_CORE = True

    def __setattr__(self, attr, value):
        if attr == "settings":
            super().__setattr__(attr, value)
        else:
            setattr(_oauth2_settings, attr, value)
            _oauth2_settings._cached_attrs.add(attr)

    def __delattr__(self, attr):
        delattr(_oauth2_settings, attr)
        if attr in _oauth2_settings._cached_attrs:
            _oauth2_settings._cached_attrs.remove(attr)

    def __getattr__(self, attr):
        return getattr(_oauth2_settings, attr)

    def finalize(self):
        self.settings.finalize()
        _oauth2_settings.reload()


@pytest.fixture
def oauth2_settings(request, settings):
    """
    A fixture that provides a simple way to override OAUTH2_PROVIDER settings.

    It can be used two ways - either setting things on the fly, or by reading
    configuration data from the pytest marker oauth2_settings.

    If used on a standard pytest function, you can use argument dependency
    injection to get the wrapper. If used on a unittest.TestCase, the wrapper
    is made available on the class instance, as `oauth2_settings`.

    Anything overridden will be restored at the end of the test case, ensuring
    that there is no configuration leakage between test cases.
    """
    marker = request.node.get_closest_marker("oauth2_settings")
    user_settings = {}
    if marker is not None:
        user_settings = marker.args[0]
    wrapper = OAuthSettingsWrapper(settings, user_settings)
    if request.instance is not None:
        request.instance.oauth2_settings = wrapper
    yield wrapper
    wrapper.finalize()


@pytest.fixture(scope="session")
def oidc_key_():
    return jwk.JWK.from_pem(test_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))


@pytest.fixture
def oidc_key(request, oidc_key_):
    if request.instance is not None:
        request.instance.key = oidc_key_
    return oidc_key_


@pytest.fixture
def application():
    return Application.objects.create(
        name="Test Application",
        redirect_uris="http://example.org",
        post_logout_redirect_uris="http://example.org",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        algorithm=Application.RS256_ALGORITHM,
        client_secret=CLEARTEXT_SECRET,
    )


@pytest.fixture
def public_application():
    return Application.objects.create(
        name="Other Application",
        redirect_uris="http://other.org",
        post_logout_redirect_uris="http://other.org",
        client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        algorithm=Application.RS256_ALGORITHM,
        client_secret=CLEARTEXT_SECRET,
    )


@pytest.fixture
def cors_application():
    return Application.objects.create(
        name="Test CORS Application",
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        algorithm=Application.RS256_ALGORITHM,
        client_secret=CLEARTEXT_SECRET,
        allowed_origins="https://example.com http://example.com",
    )


@pytest.fixture
def logged_in_client(test_user):
    from django.test.client import Client

    client = Client()
    client.force_login(test_user)
    return client


@pytest.fixture
def hybrid_application(application):
    application.authorization_grant_type = application.GRANT_OPENID_HYBRID
    application.client_secret = CLEARTEXT_SECRET
    application.save()
    return application


@pytest.fixture
def test_user():
    return UserModel.objects.create_user("test_user", "test@example.com", "123456")


@pytest.fixture
def other_user():
    return UserModel.objects.create_user("other_user", "other@example.com", "123456")


@pytest.fixture
def rp_settings(oauth2_settings):
    oauth2_settings.update(presets.OIDC_SETTINGS_RP_LOGOUT)
    return oauth2_settings


def generate_access_token(oauth2_settings, application, test_user, client, settings, scope, redirect_uri):
    """
    A helper function that generates an access_token and ID Token for a given Application and User.
    """
    oauth2_settings.update(settings)
    client.force_login(test_user)
    auth_rsp = client.post(
        reverse("oauth2_provider:authorize"),
        data={
            "client_id": application.client_id,
            "state": "random_state_string",
            "scope": scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "allow": True,
        },
    )
    assert auth_rsp.status_code == 302
    code = parse_qs(urlparse(auth_rsp["Location"]).query)["code"]
    client.logout()
    token_rsp = client.post(
        reverse("oauth2_provider:token"),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": application.client_id,
            "client_secret": CLEARTEXT_SECRET,
            "scope": scope,
        },
    )
    assert token_rsp.status_code == 200
    token_data = token_rsp.json()
    return SimpleNamespace(
        user=test_user,
        application=application,
        access_token=token_data["access_token"],
        id_token=token_data["id_token"],
        oauth2_settings=oauth2_settings,
    )


@pytest.fixture
def expired_id_token(oauth2_settings, oidc_key, test_user, application):
    payload = generate_id_token_payload(oauth2_settings, application, oidc_key)
    return generate_id_token(test_user, payload, oidc_key, application)


@pytest.fixture
def id_token_wrong_aud(oauth2_settings, oidc_key, test_user, application):
    payload = generate_id_token_payload(oauth2_settings, application, oidc_key)
    payload[1]["aud"] = ""
    return generate_id_token(test_user, payload, oidc_key, application)


@pytest.fixture
def id_token_wrong_iss(oauth2_settings, oidc_key, test_user, application):
    payload = generate_id_token_payload(oauth2_settings, application, oidc_key)
    payload[1]["iss"] = ""
    return generate_id_token(test_user, payload, oidc_key, application)


def generate_id_token_payload(oauth2_settings, application, oidc_key):
    # Default leeway of JWT in jwcrypto is 60 seconds. This means that tokens that expired up to 60 seconds
    # ago are still accepted.
    expiration_time = timezone.now() - timedelta(seconds=61)
    # Calculate values for the IDToken
    exp = int(dateformat.format(expiration_time, "U"))
    jti = str(uuid.uuid4())
    aud = application.client_id
    iss = oauth2_settings.OIDC_ISS_ENDPOINT
    # Construct and sign the IDToken
    header = {"typ": "JWT", "alg": "RS256", "kid": oidc_key.thumbprint()}
    id_token = {"exp": exp, "jti": jti, "aud": aud, "iss": iss}
    return header, id_token, jti, expiration_time


def generate_id_token(user, payload, oidc_key, application):
    header, id_token, jti, expiration_time = payload
    jwt_token = jwt.JWT(header=header, claims=id_token)
    jwt_token.make_signed_token(oidc_key)
    # Save the IDToken in the DB. Required for later lookups from e.g. RP-Initiated Logout.
    IDToken = get_id_token_model()
    IDToken.objects.create(user=user, scope="", expires=expiration_time, jti=jti, application=application)
    # Return the token as a string.
    return jwt_token.token.serialize(compact=True)


@pytest.fixture
def oidc_tokens(oauth2_settings, application, test_user, client):
    return generate_access_token(
        oauth2_settings,
        application,
        test_user,
        client,
        presets.OIDC_SETTINGS_RW,
        "openid",
        "http://example.org",
    )


@pytest.fixture
def oidc_email_scope_tokens(oauth2_settings, application, test_user, client):
    return generate_access_token(
        oauth2_settings,
        application,
        test_user,
        client,
        presets.OIDC_SETTINGS_EMAIL_SCOPE,
        "openid email",
        "http://example.org",
    )


@pytest.fixture
def oidc_non_confidential_tokens(oauth2_settings, public_application, test_user, client):
    return generate_access_token(
        oauth2_settings,
        public_application,
        test_user,
        client,
        presets.OIDC_SETTINGS_EMAIL_SCOPE,
        "openid",
        "http://other.org",
    )


@pytest.fixture(autouse=True)
def django_login_required_middleware(settings, request):
    if "nologinrequiredmiddleware" in request.keywords:
        return

    # Django 5.1 introduced LoginRequiredMiddleware
    if VERSION[0] >= 5 and VERSION[1] >= 1:
        settings.MIDDLEWARE = [*settings.MIDDLEWARE, "django.contrib.auth.middleware.LoginRequiredMiddleware"]
