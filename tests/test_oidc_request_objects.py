"""OpenID Connect request objects (OpenID Connect Core 1.0 section 6).

With ``OIDC_REQUEST_OBJECTS_ENABLED`` the authorization endpoint accepts a
request object by value (``request``) or by reference (``request_uri``),
validates it and assembles the authorization request from it and the OAuth 2.0
parameters, the request object's values winning (section 6.3.3). With the
setting off, ``tests/test_authorization_request_objects.py`` covers the
rejection.
"""

import datetime
import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwk, jws, jwt
from jwcrypto.common import base64url_encode
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError
from oauthlib.openid.connect.core.exceptions import InvalidRequestObject, InvalidRequestURI

from oauth2_provider.authorization_server import client_assertions
from oauth2_provider.authorization_server.oidc import request_objects
from oauth2_provider.authorization_server.oidc.request_objects import (
    RequestObjectError,
    RequestURIFetchError,
    SafeRequestURIFetcher,
    resolve_request_object,
)
from oauth2_provider.authorization_server.stored_requests import REQUEST_URI_PREFIX
from oauth2_provider.core import safe_fetch
from oauth2_provider.models import (
    create_stored_authorization_request,
    get_application_model,
    get_grant_model,
    get_stored_authorization_request_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import OAuth2ProviderSettings

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
Grant = get_grant_model()
StoredAuthorizationRequest = get_stored_authorization_request_model()
UserModel = get_user_model()

ISSUER = presets.OIDC_SETTINGS_RW["OIDC_ISS_ENDPOINT"]
REQUEST_URI = "https://client.example/requests/1.jwt"
CLIENT_KEY = jwk.JWK.generate(kty="RSA", size=2048, kid="client-rsa")
CLIENT_EC_KEY = jwk.JWK.generate(kty="EC", crv="P-256", kid="client-ec")
OTHER_KEY = jwk.JWK.generate(kty="RSA", size=2048, kid="client-rsa")
NONE_HEADER = base64url_encode(json.dumps({"alg": "none"}))


def _jwks(*keys):
    return json.dumps({"keys": [json.loads(key.export_public()) for key in keys]})


def unsigned(claims, header=None):
    header = header or {"alg": "none"}
    return f"{base64url_encode(json.dumps(header))}.{base64url_encode(json.dumps(claims))}."


def signed(claims, key=CLIENT_KEY, alg="RS256", **header):
    token = jwt.JWT(header={"alg": alg, "kid": key.kid, **header}, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


class _StubFetcher:
    """An OIDC_REQUEST_URI_FETCHER returning a fixed document and recording calls."""

    document = ""
    calls = []

    def fetch(self, request_uri):
        type(self).calls.append(request_uri)
        if isinstance(self.document, Exception):
            raise self.document
        return self.document


def stub_fetcher(document):
    return type("Fetcher", (_StubFetcher,), {"document": document, "calls": []})


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_REQUEST_OBJECTS)
class TestRequestObjects(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.application = Application.objects.create(
            name="Code Application",
            redirect_uris="http://example.org http://example.org/other",
            user=dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            algorithm=Application.RS256_ALGORITHM,
            client_jwks=_jwks(CLIENT_KEY, CLIENT_EC_KEY),
        )

    def setUp(self):
        cache.clear()
        self.client.login(username="test_user", password="123456")

    def tearDown(self):
        cache.clear()

    def authorize(self, method="get", **params):
        query = {
            "client_id": self.application.client_id,
            "response_type": "code",
            "redirect_uri": "http://example.org",
            "scope": "openid",
            "state": "outer_state",
        }
        query.update(params)
        send = getattr(self.client, method)
        return send(reverse("oauth2_provider:authorize"), {k: v for k, v in query.items() if v is not None})

    def claims(self, **overrides):
        claims = {
            "iss": self.application.client_id,
            "aud": ISSUER,
            "client_id": self.application.client_id,
            "response_type": "code",
            "redirect_uri": "http://example.org/other",
            "scope": "openid",
            "state": "inner_state",
            "nonce": "inner_nonce",
            "exp": int(time.time()) + 300,
        }
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not None}

    def assertErrorRedirect(self, response, error, state="outer_state"):
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        # Errors only go to the redirect URI sent with the OAuth 2.0 syntax.
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", "http://example.org")
        params = parse_qs(location.query)
        self.assertEqual(params["error"], [error])
        if state is None:
            self.assertNotIn("state", params)
        else:
            self.assertEqual(params["state"], [state])
        return params

    def stored(self, response):
        """The stored request *response* redirects to, its parameters as lists."""
        self.assertEqual(response.status_code, 302, response.content)
        location = urlparse(response["Location"])
        self.assertEqual(location.path, reverse("oauth2_provider:authorize"))
        # Only a reference to the assembled request enters the URL.
        query = parse_qs(location.query)
        self.assertEqual(set(query), {"client_id", "request_uri"})
        self.assertEqual(query["client_id"], [self.application.client_id])
        self.assertTrue(query["request_uri"][0].startswith(REQUEST_URI_PREFIX))
        record = StoredAuthorizationRequest.objects.get(request_uri=query["request_uri"][0])
        self.assertEqual(record.client_id, self.application.client_id)
        return {
            name: value if isinstance(value, list) else [value] for name, value in record.parameters.items()
        }

    def assertResolved(self, response, state="inner_state", nonce="inner_nonce"):
        """Assert *response* redirects back to the endpoint with a stored request.

        Follows the redirect, checks the page with :meth:`assertResolvedPage`,
        and returns the stored parameters.
        """
        params = self.stored(response)
        self.assertNotIn("request", params)
        self.assertNotIn("request_uri", params)
        self.assertEqual(params["state"], [state])
        self.assertEqual(params["nonce"], [nonce])
        self.assertResolvedPage(self.client.get(response["Location"]), state)
        return params

    def assertResolvedPage(self, response, state):
        # A logged-in end-user is shown the consent form for the assembled request.
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.context_data["state"], state)

    def consent(self, response):
        """Follow the redirect to the stored request and approve it."""
        page = self.client.get(response["Location"])
        form = {k: v for k, v in page.context_data["form"].initial.items() if v is not None}
        # The consent form has no action, so it posts back to the URL it was served from.
        return self.client.post(response["Location"], {**form, "allow": True})

    # -- by value ---------------------------------------------------------

    def test_unsigned_request_object_supersedes_query_parameters(self):
        params = self.assertResolved(self.authorize(request=unsigned(self.claims())))
        self.assertEqual(params["redirect_uri"], ["http://example.org/other"])

    def test_query_parameters_fill_in_what_the_request_object_omits(self):
        response = self.authorize(request=unsigned(self.claims(state=None, nonce=None)), nonce="outer_nonce")
        self.assertResolved(response, state="outer_state", nonce="outer_nonce")

    def test_signed_request_objects(self):
        for key, alg in [(CLIENT_KEY, "RS256"), (CLIENT_KEY, "PS384"), (CLIENT_EC_KEY, "ES256")]:
            with self.subTest(alg=alg):
                self.assertResolved(self.authorize(request=signed(self.claims(), key=key, alg=alg)))

    def test_signed_request_object_without_kid_or_iss_and_aud(self):
        token = jwt.JWT(header={"alg": "RS256"}, claims=self.claims(iss=None, aud=None))
        token.make_signed_token(CLIENT_KEY)
        self.assertResolved(self.authorize(request=token.serialize()))

    def test_keys_sharing_a_kid(self):
        # jwcrypto refuses to pick between keys sharing a kid; each is tried.
        other_with_same_kid = jwk.JWK.generate(kty="RSA", size=2048, kid="client-rsa")
        self.application.client_jwks = _jwks(other_with_same_kid, CLIENT_KEY)
        self.application.save()
        self.assertResolved(self.authorize(request=signed(self.claims())))
        self.assertErrorRedirect(
            self.authorize(request=signed(self.claims(), key=OTHER_KEY)), "invalid_request_object"
        )

    def test_signed_request_object_audience_may_be_a_list(self):
        claims = self.claims(aud=["https://other.example", ISSUER])
        self.assertResolved(self.authorize(request=signed(claims)))

    def test_signed_request_object_audience_is_compared_exactly(self):
        # RFC 7519 section 2: StringOrURI values are compared without normalization.
        for aud in [ISSUER + "/", [ISSUER + "/"], ISSUER.upper()]:
            with self.subTest(aud=aud):
                response = self.authorize(request=signed(self.claims(aud=aud)))
                self.assertErrorRedirect(response, "invalid_request_object")

    def test_signed_request_object_with_jwks_uri(self):
        self.application.client_jwks = ""
        self.application.client_jwks_uri = "https://client.example/jwks.json"
        self.application.save()
        document = json.loads(_jwks(CLIENT_KEY))
        with mock.patch.object(
            client_assertions.safe_fetch, "fetch_https_json", return_value=(document, {})
        ) as fetch:
            self.assertResolved(self.authorize(request=signed(self.claims())))
        fetch.assert_called_once()

    def test_consent_uses_the_request_object(self):
        response = self.consent(self.authorize(request=unsigned(self.claims(prompt="consent"))))
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", "http://example.org/other")
        params = parse_qs(location.query)
        self.assertEqual(params["state"], ["inner_state"])
        self.assertEqual(Grant.objects.get(code=params["code"][0]).nonce, "inner_nonce")

    def test_hybrid_response_type_in_another_order(self):
        hybrid = Application.objects.create(
            name="Hybrid Application",
            redirect_uris="http://example.org",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_OPENID_HYBRID,
            algorithm=Application.RS256_ALGORITHM,
            skip_authorization=True,
        )
        claims = self.claims(client_id=hybrid.client_id, response_type="id_token code", redirect_uri=None)
        response = self.authorize(
            client_id=hybrid.client_id, response_type="code id_token", request=unsigned(claims)
        )
        self.application = hybrid  # whose request stored() looks up
        self.assertEqual(self.stored(response)["response_type"], ["code id_token"])
        # The validator compares response_type with the registered grant as a string.
        location = urlparse(self.client.get(response["Location"])["Location"])
        params = parse_qs(location.fragment)
        self.assertNotIn("error", params)
        self.assertIn("code", params)
        self.assertIn("id_token", params)
        self.assertEqual(params["state"], ["inner_state"])

    def test_request_object_sent_by_post(self):
        # OpenID Connect Core 1.0 section 3.1.2.1: the request may be POSTed; it is
        # redirected to its GET form, where the request object is resolved.
        response = self.authorize(method="post", request=unsigned(self.claims()))
        self.assertEqual(response.status_code, 303)
        self.assertIn("request=", response["Location"])
        self.assertResolved(self.client.get(response["Location"]))

    def test_redirect_uri_only_in_request_object(self):
        # oidcc-ensure-request-object-with-redirect-uri: the redirect URI is
        # sent only inside the request object.
        response = self.authorize(request=unsigned(self.claims()), redirect_uri=None)
        self.assertResolved(response)

    def test_claims_parameter_round_trips(self):
        claims_request = {"userinfo": {"email": {"essential": True}}}
        response = self.authorize(request=unsigned(self.claims(claims=claims_request, max_age=60)))
        params = self.assertResolved(response)
        self.assertEqual(json.loads(params["claims"][0]), claims_request)
        self.assertEqual(params["max_age"], ["60"])

    def test_invalid_request_objects(self):
        cases = {
            "not a jwt": "not-a-jwt",
            "encrypted": "a.b.c.d.e",
            "bad header": "e30x.e30.",
            "header not an object": f"{base64url_encode('[]')}.{base64url_encode('{}')}.",
            "payload not an object": f"{NONE_HEADER}.{base64url_encode('[1]')}.",
            "unsigned with a signature": unsigned(self.claims())[:-1] + ".c2ln",
            "unsigned with crit": unsigned(self.claims(), header={"alg": "none", "crit": ["exp"]}),
            "symmetric alg": unsigned(self.claims(), header={"alg": "HS256"}),
            "alg missing": unsigned(self.claims(), header={"typ": "JWT"}),
            "wrong key": signed(self.claims(), key=OTHER_KEY),
            "alg not matching key": signed(self.claims(), key=CLIENT_EC_KEY, alg="ES256", kid="client-rsa"),
            "expired": unsigned(self.claims(exp=int(time.time()) - 3600)),
            "not yet valid": unsigned(self.claims(nbf=int(time.time()) + 3600)),
            "exp not a number": unsigned(self.claims(exp="tomorrow")),
            "exp not finite": NONE_HEADER + "." + base64url_encode('{"exp": Infinity}') + ".",
            # Exact JSON integers far beyond the float range.
            "exp long past": unsigned(self.claims(exp=-(10**400))),
            "nbf too far": unsigned(self.claims(nbf=10**400)),
            "nbf not a number": NONE_HEADER + "." + base64url_encode('{"nbf": NaN}') + ".",
            "client_id mismatch": unsigned(self.claims(client_id="someone-else")),
            "response_type mismatch": unsigned(self.claims(response_type="token")),
            "nested request": unsigned(self.claims(request="x.y.")),
            "nested request_uri": unsigned(self.claims(request_uri=REQUEST_URI)),
            "iss not the client": signed(self.claims(iss="https://attacker.example")),
            "aud not this issuer": signed(self.claims(aud="https://other-op.example")),
            # Deep nesting overflows the JSON parser's recursion limit.
            "deeply nested header": f"{base64url_encode('[' * 5000 + ']' * 5000)}.e30.",
            "deeply nested payload": f"{NONE_HEADER}.{base64url_encode('[' * 5000 + ']' * 5000)}.",
            # Lone UTF-16 surrogates decode from JSON escapes but cannot be encoded.
            "surrogate in a value": NONE_HEADER + "." + base64url_encode(r'{"state": "\ud800"}') + ".",
            "surrogate in a name": NONE_HEADER + "." + base64url_encode(r'{"\ud800": "x"}') + ".",
            "surrogate in a signed object": signed(self.claims(state="\ud800")),
        }
        for case, request_object in cases.items():
            with self.subTest(case=case):
                response = self.authorize(request=request_object)
                params = self.assertErrorRedirect(response, "invalid_request_object")
                self.assertIn("error_description", params)

    def test_registered_signing_alg_is_enforced(self):
        self.application.request_object_signing_alg = "RS256"
        self.application.save()
        self.assertErrorRedirect(self.authorize(request=unsigned(self.claims())), "invalid_request_object")
        self.assertErrorRedirect(
            self.authorize(request=signed(self.claims(), key=CLIENT_EC_KEY, alg="ES256")),
            "invalid_request_object",
        )
        self.assertResolved(self.authorize(request=signed(self.claims())))

    def test_registered_none_alg_refuses_signed_request_objects(self):
        self.application.request_object_signing_alg = "none"
        self.application.save()
        self.assertErrorRedirect(self.authorize(request=signed(self.claims())), "invalid_request_object")
        self.assertResolved(self.authorize(request=unsigned(self.claims())))

    def test_header_alg_is_not_echoed(self):
        alg = 'x"<b>' + "A" * 100
        params = self.assertErrorRedirect(
            self.authorize(request=unsigned(self.claims(), header={"alg": alg})), "invalid_request_object"
        )
        self.assertNotIn("<b>", params["error_description"][0])
        self.assertNotIn('"', params["error_description"][0])

    def test_signing_alg_outside_the_setting_is_refused(self):
        self.oauth2_settings.OIDC_REQUEST_OBJECT_SIGNING_ALGS = ["RS256"]
        self.assertErrorRedirect(self.authorize(request=unsigned(self.claims())), "invalid_request_object")
        self.assertResolved(self.authorize(request=signed(self.claims())))

    def test_signed_request_object_without_registered_keys(self):
        self.application.client_jwks = ""
        self.application.save()
        self.assertErrorRedirect(self.authorize(request=signed(self.claims())), "invalid_request_object")

    def test_invalid_request_object_error_uses_outer_state_only(self):
        response = self.authorize(request=signed(self.claims(), key=OTHER_KEY), state=None)
        self.assertErrorRedirect(response, "invalid_request_object", state=None)

    def test_invalid_request_object_without_outer_redirect_uri_is_not_redirected(self):
        response = self.authorize(request=signed(self.claims(), key=OTHER_KEY), redirect_uri=None)
        self.assertEqual(response.status_code, 400)

    def test_unknown_client_is_not_redirected(self):
        response = self.authorize(client_id="unknown", request=unsigned(self.claims()))
        self.assertEqual(response.status_code, 400)

    def test_client_is_loaded_with_the_request_headers(self):
        # is_usable() overrides and CIMD permission classes see the real request.
        with mock.patch.object(
            OAuth2Validator, "_load_application", autospec=True, side_effect=OAuth2Validator._load_application
        ) as load:
            self.client.get(
                reverse("oauth2_provider:authorize"),
                {
                    "client_id": self.application.client_id,
                    "response_type": "code",
                    "request": unsigned(self.claims()),
                },
                REMOTE_ADDR="203.0.113.9",
            )
        oauthlib_request = load.call_args_list[0].args[2]
        self.assertEqual(oauthlib_request.headers["REMOTE_ADDR"], "203.0.113.9")
        self.assertEqual(oauthlib_request.http_method, "GET")

    def test_malformed_percent_escape_in_the_query(self):
        # Django decodes it leniently; the client lookup must not trip over it.
        for method in ("get", "head"):
            with self.subTest(method=method):
                query = urlencode(
                    {
                        "client_id": self.application.client_id,
                        "response_type": "code",
                        "redirect_uri": "http://example.org",
                        "scope": "openid",
                        "state": "outer_state",
                        "request": signed(self.claims(), key=OTHER_KEY),
                    }
                )
                response = getattr(self.client, method)(
                    f"{reverse('oauth2_provider:authorize')}?{query}&x=%ZZ"
                )
                self.assertErrorRedirect(response, "invalid_request_object")

    def test_missing_client_id_is_not_redirected(self):
        response = self.authorize(client_id=None, request=unsigned(self.claims()))
        self.assertEqual(response.status_code, 400)

    def test_request_and_request_uri_together(self):
        response = self.authorize(request=unsigned(self.claims()), request_uri=REQUEST_URI)
        self.assertErrorRedirect(response, "invalid_request")

    def test_outer_response_type_and_openid_scope_are_required(self):
        # Sections 6.1 and 6.2: the request object supplying them is not enough.
        cases = {
            "response_type missing": {"response_type": None},
            "scope missing": {"scope": None},
            "scope without openid": {"scope": "read"},
        }
        fetcher = stub_fetcher(unsigned(self.claims(scope="openid read")))
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
        for case, params in cases.items():
            with self.subTest(case=case):
                response = self.authorize(request=unsigned(self.claims(scope="openid read")), **params)
                self.assertErrorRedirect(response, "invalid_request")
                response = self.authorize(request_uri=REQUEST_URI, **params)
                self.assertErrorRedirect(response, "invalid_request")
        self.assertEqual(fetcher.calls, [])

    def test_repeated_request_parameter(self):
        for values in [[unsigned(self.claims()), unsigned(self.claims())], [unsigned(self.claims()), ""]]:
            with self.subTest(values=values):
                response = self.authorize(request=values)
                self.assertErrorRedirect(response, "invalid_request")
        response = self.authorize(request_uri=[REQUEST_URI, ""])
        self.assertErrorRedirect(response, "invalid_request")

    def test_repeated_parameter_is_not_hidden_by_the_request_object(self):
        # RFC 6749 section 3.1: the request object superseding a repeated
        # parameter does not make the request valid. The outcome is the one
        # without a request object.
        response = self.authorize(request=unsigned(self.claims(nonce="inner")), nonce=["a", "b"])
        self.assertErrorRedirect(response, "invalid_request")
        # The name comes from the request object and is not echoed.
        name = 'x"<b>\u00e9'
        response = self.authorize(request=unsigned(self.claims(**{name: "v"})), **{name: ["a", "b"]})
        params = self.assertErrorRedirect(response, "invalid_request")
        self.assertNotIn(name, params["error_description"][0])
        # oauthlib treats these as fatal, so the error is shown to the user.
        for name, values in {
            "state": ["a", "b"],
            "client_id": ["someone-else", self.application.client_id],
            "redirect_uri": ["http://example.org", "http://example.org/other"],
        }.items():
            with self.subTest(name=name):
                response = self.authorize(request=unsigned(self.claims()), **{name: values})
                self.assertEqual(response.status_code, 400)

    def test_assembled_request_is_validated_before_it_is_stored(self):
        # Validated in full, as the store requires, and reported before any login
        # (OpenID Connect Core 1.0 sections 3.1.2.2 and 3.1.2.3), with the
        # response the normal flow gives.
        response = self.authorize(request=unsigned(self.claims(redirect_uri="http://attacker.example")))
        self.assertEqual(response.status_code, 400)
        cases = {
            "malformed max_age": {"request": unsigned(self.claims(max_age="abc"))},
            # A repeat the request object does not supersede.
            "repeated prompt": {"request": unsigned(self.claims()), "prompt": ["login", "consent"]},
        }
        for case, params in cases.items():
            with self.subTest(case=case):
                response = self.authorize(**params)
                self.assertEqual(response.status_code, 302)
                location = urlparse(response["Location"])
                # The assembled redirect_uri, which oauthlib has validated.
                self.assertEqual(
                    f"{location.scheme}://{location.netloc}{location.path}", "http://example.org/other"
                )
                query = parse_qs(location.query)
                self.assertEqual(query["error"], ["invalid_request"])
                self.assertEqual(query["state"], ["inner_state"])
        self.assertFalse(StoredAuthorizationRequest.objects.exists())

    def test_head_request(self):
        self.application.skip_authorization = True
        self.application.save()
        response = self.authorize(method="head", request=signed(self.claims(), key=OTHER_KEY))
        self.assertErrorRedirect(response, "invalid_request_object")

    def test_par_request_uri_is_still_resolved(self):
        par = create_stored_authorization_request(
            request_uri=f"{REQUEST_URI_PREFIX}test-reference-value",
            client_id=self.application.client_id,
            parameters={
                "client_id": self.application.client_id,
                "response_type": "code",
                "redirect_uri": "http://example.org",
                "scope": "openid",
                "state": "pushed_state",
            },
            expires_in=60,
        )
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {"client_id": self.application.client_id, "request_uri": par.request_uri},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context_data["state"], "pushed_state")

    def test_par_required_client_gets_par_error(self):
        self.application.require_pushed_authorization_requests = True
        self.application.save()
        response = self.authorize(request=unsigned(self.claims()))
        self.assertEqual(response.status_code, 400)
        self.assertIn("required for this client", response.content.decode().lower())

    def test_disabled_without_oidc(self):
        # Request objects are an OpenID Connect feature.
        self.oauth2_settings.OIDC_ENABLED = False
        response = self.authorize(request=unsigned(self.claims()), scope="read")
        self.assertErrorRedirect(response, "request_not_supported")

    # -- the stored request -----------------------------------------------

    def redirects(self, response, limit=5):
        """Follow *response*'s redirects on this server, yielding each Location."""
        for _ in range(limit):
            if response.status_code not in (301, 302, 303) or not response["Location"].startswith("/"):
                return
            yield response["Location"]
            response = self.client.get(response["Location"])

    def test_assembled_request_stays_out_of_every_url(self):
        # OpenID Connect Core 1.0 section 6: the request object's contents are
        # neither exposed in nor editable through the browser URL.
        marker = "marker-7f3a"
        claims = self.claims(
            state=f"{marker}-state",
            nonce=f"{marker}-nonce",
            login_hint=f"{marker}@example.com",
            claims={"userinfo": {f"{marker}_claim": None}},
        )
        locations = list(self.redirects(self.authorize(request=unsigned(claims))))
        self.assertTrue(locations)
        for location in locations:
            self.assertNotIn(marker, location)
            self.assertNotIn("http%3A%2F%2Fexample.org%2Fother", location)

    def test_large_request_object_stays_out_of_the_url(self):
        # Larger than Django lets a redirect URL be: only the reference is sent.
        claims = self.claims(login_hint="x" * 10000)
        params = self.stored(self.authorize(request=unsigned(claims)))
        self.assertEqual(params["login_hint"], ["x" * 10000])

    def test_client_authentication_parameters_are_not_stored(self):
        params = self.stored(self.authorize(request=unsigned(self.claims()), client_secret="secret"))
        self.assertNotIn("client_secret", params)

    def test_stored_request_lifetime(self):
        self.oauth2_settings.OIDC_REQUEST_OBJECT_STORE_LIFETIME_SECONDS = 120
        before = timezone.now()
        response = self.authorize(request=unsigned(self.claims()))
        request_uri = parse_qs(urlparse(response["Location"]).query)["request_uri"][0]
        expires = StoredAuthorizationRequest.objects.get(request_uri=request_uri).expires
        self.assertGreaterEqual(expires, before + datetime.timedelta(seconds=120))
        self.assertLessEqual(expires, timezone.now() + datetime.timedelta(seconds=120))

    def test_expired_stored_request(self):
        response = self.authorize(request=unsigned(self.claims()))
        StoredAuthorizationRequest.objects.update(expires=timezone.now() - datetime.timedelta(seconds=1))
        self.client.login(username="test_user", password="123456")
        response = self.client.get(response["Location"])
        self.assertEqual(response.status_code, 400)
        self.assertIn("expired", response.content.decode())

    def test_stored_request_is_single_use_and_authoritative(self):
        response = self.authorize(request=unsigned(self.claims()))
        self.client.login(username="test_user", password="123456")
        # Parameters sent beside the reference are ignored: the stored request is
        # authoritative, so nothing the request object fixed can be changed.
        page = self.client.get(response["Location"] + "&state=tampered&redirect_uri=http%3A%2F%2Fexample.org")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.context_data["state"], "inner_state")
        self.assertEqual(page.context_data["redirect_uri"], "http://example.org/other")
        # Used up by that request.
        self.assertEqual(self.client.get(response["Location"]).status_code, 400)

    def test_stored_request_is_bound_to_the_client(self):
        other = Application.objects.create(
            name="Other Application",
            redirect_uris="http://example.org",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        response = self.authorize(request=unsigned(self.claims()))
        request_uri = parse_qs(urlparse(response["Location"]).query)["request_uri"][0]
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            reverse("oauth2_provider:authorize"), {"client_id": other.client_id, "request_uri": request_uri}
        )
        self.assertEqual(response.status_code, 400)
        # Left intact for the client it was issued to.
        self.assertTrue(StoredAuthorizationRequest.objects.filter(request_uri=request_uri).exists())

    # -- by reference -----------------------------------------------------

    def test_request_uri(self):
        fetcher = stub_fetcher(signed(self.claims()))
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
        self.assertResolved(self.authorize(request_uri=REQUEST_URI))
        self.assertEqual(fetcher.calls, [REQUEST_URI])

    def test_request_uri_matching_a_registered_one(self):
        self.application.request_uris = f"https://client.example/other {REQUEST_URI}#v1"
        self.application.save()
        fetcher = stub_fetcher(unsigned(self.claims()))
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
        # The fragment identifies a version of the document, not the URI.
        self.assertResolved(self.authorize(request_uri=f"{REQUEST_URI}#v2"))
        self.assertEqual(fetcher.calls, [f"{REQUEST_URI}#v2"])

    def test_unregistered_request_uri_is_not_fetched(self):
        self.application.request_uris = "https://client.example/other"
        self.application.save()
        fetcher = stub_fetcher(unsigned(self.claims()))
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
        self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")
        self.assertEqual(fetcher.calls, [])

    def test_malformed_request_uri(self):
        # The stock fetcher: URL parsing and host name encoding fail before any connection.
        for request_uri in ["https://[::1/x", "https://a..b/x", "https://exa\u2100mple.com/x"]:
            with self.subTest(request_uri=request_uri):
                self.assertErrorRedirect(self.authorize(request_uri=request_uri), "invalid_request_uri")

    def test_request_uri_fetch_failures(self):
        # A fetcher raising outside its contract (RuntimeError) is answered the same way.
        for document in [
            RequestURIFetchError("boom"),
            safe_fetch.SafeFetchError("refused"),
            RuntimeError("unexpected"),
            "",
        ]:
            with self.subTest(document=document):
                cache.clear()  # the failure backoff
                self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = stub_fetcher(document)
                self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")

    def test_failed_request_uri_is_not_fetched_again_for_a_while(self):
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = stub_fetcher(RequestURIFetchError("down"))
        self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")
        fetcher = stub_fetcher(unsigned(self.claims()))
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
        # The backoff covers the URI whatever its fragment.
        self.assertErrorRedirect(self.authorize(request_uri=f"{REQUEST_URI}#v2"), "invalid_request_uri")
        self.assertEqual(fetcher.calls, [])
        cache.clear()
        self.assertResolved(self.authorize(request_uri=REQUEST_URI))

    def test_failure_backoff_can_be_disabled(self):
        # None must not reach the cache, where it would mean "never expires".
        for backoff in (0, None):
            with self.subTest(backoff=backoff):
                cache.clear()
                self.oauth2_settings.OIDC_REQUEST_URI_FAILURE_BACKOFF_SECONDS = backoff
                self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = stub_fetcher(RequestURIFetchError("down"))
                self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")
                fetcher = stub_fetcher(unsigned(self.claims()))
                self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
                self.assertResolved(self.authorize(request_uri=REQUEST_URI))
                self.assertEqual(fetcher.calls, [REQUEST_URI])

    def test_request_uri_fetches_in_flight_are_capped(self):
        self.oauth2_settings.OIDC_REQUEST_URI_MAX_CONCURRENT_FETCHES = 1
        fetcher = stub_fetcher(unsigned(self.claims()))
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
        with request_objects._fetch_slot() as acquired:
            self.assertTrue(acquired)
            self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")
        self.assertEqual(fetcher.calls, [])
        # A refused fetch arms no backoff, and the slot is free again.
        self.assertResolved(self.authorize(request_uri=REQUEST_URI))
        for disabled in (0, None):
            with self.subTest(cap=disabled):
                self.oauth2_settings.OIDC_REQUEST_URI_MAX_CONCURRENT_FETCHES = disabled
                with request_objects._fetch_slot() as acquired, request_objects._fetch_slot() as also:
                    self.assertTrue(acquired and also)

    def test_request_uri_with_invalid_request_object(self):
        # Section 3.1.2.6: a request_uri whose document is invalid "contains invalid data".
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = stub_fetcher(signed(self.claims(), key=OTHER_KEY))
        self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")

    def test_request_uri_with_invalid_unicode(self):
        document = NONE_HEADER + "." + base64url_encode(r'{"nonce": "\udfff"}') + "."
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = stub_fetcher(document)
        self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")

    def test_request_uri_with_registered_signing_alg(self):
        self.application.request_object_signing_alg = "RS256"
        self.application.save()
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = stub_fetcher(unsigned(self.claims()))
        self.assertErrorRedirect(self.authorize(request_uri=REQUEST_URI), "invalid_request_uri")

    def test_request_uri_is_fetched_once(self):
        # The consent POST goes to the assembled request, so it neither fetches
        # the request_uri again nor depends on it still being there.
        fetcher = stub_fetcher(unsigned(self.claims()))
        self.oauth2_settings.OIDC_REQUEST_URI_FETCHER = fetcher
        response = self.consent(self.authorize(request_uri=REQUEST_URI))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(parse_qs(urlparse(response["Location"]).query)["state"], ["inner_state"])
        self.assertEqual(fetcher.calls, [REQUEST_URI])


class TestRequestObjectsAnonymous(TestRequestObjects):
    """An end-user who is not logged in: the request object is resolved before login."""

    def setUp(self):
        cache.clear()

    def assertResolvedPage(self, response, state):
        # The stored request is sent to log in first, by its reference only.
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(location.path, settings.LOGIN_URL)
        next_query = parse_qs(urlparse(parse_qs(location.query)["next"][0]).query)
        self.assertEqual(set(next_query), {"client_id", "request_uri"})
        self.assertTrue(next_query["request_uri"][0].startswith(REQUEST_URI_PREFIX))

    def test_consent_uses_the_request_object(self):
        self.skipTest("Consent needs a logged-in end-user.")

    def test_request_uri_is_fetched_once(self):
        self.skipTest("Consent needs a logged-in end-user.")

    def test_hybrid_response_type_in_another_order(self):
        self.skipTest("The hybrid response needs a logged-in end-user.")

    def test_par_request_uri_is_still_resolved(self):
        self.skipTest("A PAR request_uri is only consumed after login.")

    def test_par_required_client_gets_par_error(self):
        self.skipTest("PAR is enforced after login.")

    def test_par_required_client_is_sent_to_log_in_first(self):
        # The request object is left alone, and PAR enforced once logged in.
        self.application.require_pushed_authorization_requests = True
        self.application.save()
        response = self.authorize(request=unsigned(self.claims()))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlparse(response["Location"]).path, settings.LOGIN_URL)

    def test_logging_in_resumes_the_stored_request(self):
        for prompt in (None, "login"):
            with self.subTest(prompt=prompt):
                self.client.logout()
                stored_url = self.authorize(request=unsigned(self.claims(prompt=prompt)))["Location"]
                login = self.client.get(stored_url)
                self.assertEqual(urlparse(login["Location"]).path, settings.LOGIN_URL)
                # The login it asked for satisfies prompt=login: one login only.
                self.client.login(username="test_user", password="123456")
                page = self.client.get(stored_url)
                self.assertEqual(page.status_code, 200)
                self.assertEqual(page.context_data["state"], "inner_state")

    # oauthlib asks the validator about silent login for prompt=none; deny it, as
    # for an end-user who is not logged in.
    @mock.patch.object(OAuth2Validator, "validate_silent_login", return_value=False)
    def test_prompt_none_inside_the_request_object(self, _validate_silent_login):
        # Answered at once (section 3.1.2.6): no login page, nothing stored.
        response = self.authorize(request=unsigned(self.claims(prompt="none")))
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", "http://example.org/other")
        params = parse_qs(location.query)
        self.assertEqual(params["error"], ["login_required"])
        self.assertEqual(params["state"], ["inner_state"])
        self.assertFalse(StoredAuthorizationRequest.objects.exists())

    @mock.patch.object(OAuth2Validator, "validate_silent_authorization", return_value=True, create=True)
    @mock.patch.object(OAuth2Validator, "validate_silent_login", return_value=True, create=True)
    def test_prompt_none_is_login_required_whatever_the_validator_says(self, *_mocks):
        # A validator that allows a silent login does not make an anonymous
        # end-user logged in: prompt=none is still answered with login_required.
        response = self.authorize(request=unsigned(self.claims(prompt="none")))
        self.assertEqual(response.status_code, 302)
        location = urlparse(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}{location.path}", "http://example.org/other")
        params = parse_qs(location.query)
        self.assertEqual(params["error"], ["login_required"])
        self.assertEqual(params["state"], ["inner_state"])
        self.assertFalse(StoredAuthorizationRequest.objects.exists())

    def test_prompt_create_inside_the_request_object(self):
        self.oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_ENABLED = True
        self.oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_URL = "/accounts/signup/"
        # With login or max_age=0 as well, the login registering ends with
        # satisfies them: the user is not sent to log in a second time.
        for extra in ({}, {"prompt": "login create"}, {"max_age": 0}):
            with self.subTest(**extra):
                self.client.logout()
                claims = self.claims(**{"prompt": "create", **extra})
                response = self.authorize(request=unsigned(claims))
                self.assertEqual(response.status_code, 302)
                location = urlparse(response["Location"])
                self.assertEqual(location.path, "/accounts/signup/")
                # Registration returns to the stored request, by its reference only.
                next_url = urlparse(parse_qs(location.query)["next"][0])
                self.assertEqual(set(parse_qs(next_url.query)), {"client_id", "request_uri"})
                # Registering ends logged in; create is then a no-op.
                self.client.login(username="test_user", password="123456")
                page = self.client.get(f"{next_url.path}?{next_url.query}")
                self.assertEqual(page.status_code, 200)
                self.assertEqual(page.context_data["state"], "inner_state")

    def test_prompt_create_inside_the_request_object_when_unsupported(self):
        response = self.authorize(request=unsigned(self.claims(prompt="create")))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["error"], "invalid_request")
        self.assertFalse(StoredAuthorizationRequest.objects.exists())


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_REQUEST_OBJECTS)
class TestResolveRequestObject(TestCase):
    """The resolver on its own, for what the view tests cannot see."""

    def setUp(self):
        self.application = Application(
            client_id="resolver-client",
            redirect_uris="http://example.org",
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_jwks=_jwks(CLIENT_KEY),
        )
        self.request = RequestFactory().get("/o/authorize/")

    # The parameters sections 6.1 and 6.2 require outside the request object.
    OUTER = {"client_id": ["resolver-client"], "response_type": ["code"], "scope": ["openid"]}

    def resolve(self, request_object, **parameters):
        parameters = {**self.OUTER, "request": [request_object], **parameters}
        return resolve_request_object(parameters, self.application, self.request)

    def test_assembly(self):
        claims = {
            "iss": "resolver-client",
            "aud": ISSUER,
            "exp": int(time.time()) + 60,
            "nbf": int(time.time()),
            "iat": int(time.time()),
            "jti": "abc",
            "state": "inner",
            "resource": ["https://rs1.example", "https://rs2.example"],
            "max_age": 0,
            "claims": {"id_token": {"acr": None}},
            "login_hint": None,
        }
        assembled = self.resolve(signed(claims), state=["outer"], ui_locales=["en"])
        self.assertEqual(
            assembled,
            {
                **self.OUTER,
                "state": ["inner"],
                "ui_locales": ["en"],
                "resource": ["https://rs1.example", "https://rs2.example"],
                "max_age": ["0"],
                "claims": ['{"id_token": {"acr": null}}'],
            },
        )

    def test_times_beyond_the_float_range(self):
        # Exact JSON integers are compared as integers, however large.
        self.assertEqual(self.resolve(unsigned({"exp": 10**400})), self.OUTER)
        self.assertEqual(self.resolve(unsigned({"nbf": -(10**400)})), self.OUTER)

    def test_response_type_order_does_not_matter(self):
        claims = {"response_type": "id_token code"}
        assembled = self.resolve(unsigned(claims), response_type=["code id_token"])
        # The outer spelling is kept: the validator compares it with the registered one.
        self.assertEqual(assembled["response_type"], ["code id_token"])
        # Without an outer response_type, the request object's is not enough.
        with self.assertRaises(RequestObjectError) as raised:
            self.resolve(unsigned(claims), response_type=[])
        self.assertIs(raised.exception.error_class, InvalidRequestError)
        for response_type in ["code", ["code", "id_token"]]:
            with self.subTest(response_type=response_type):
                with self.assertRaises(RequestObjectError):
                    self.resolve(unsigned({"response_type": response_type}), response_type=["code id_token"])

    def test_array_values(self):
        assembled = self.resolve(unsigned({"resource": [], "scope": ["openid", "profile"]}))
        # An empty array is absent; only resource may repeat, so an array scope
        # is passed on as its JSON text and fails scope validation.
        self.assertNotIn("resource", assembled)
        self.assertEqual(assembled["scope"], ['["openid", "profile"]'])

    def test_error_classes(self):
        cases = [
            ({"request_uri": [REQUEST_URI]}, InvalidRequestError),
            ({"request": ["a.b.", "c.d."]}, InvalidRequestError),
        ]
        for parameters, error_class in cases:
            with self.subTest(parameters=parameters):
                with self.assertRaises(RequestObjectError) as raised:
                    self.resolve(unsigned({}), **parameters)
                self.assertIs(raised.exception.error_class, error_class)
        with self.assertRaises(RequestObjectError) as raised:
            self.resolve(unsigned({}).replace(".", "", 1))
        self.assertIs(raised.exception.error_class, InvalidRequestObject)

    def test_request_uri_error_class(self):
        self.application.request_uris = "https://client.example/registered"
        with self.assertRaises(RequestObjectError) as raised:
            resolve_request_object(
                {**self.OUTER, "request_uri": [REQUEST_URI]},
                self.application,
                self.request,
            )
        self.assertIs(raised.exception.error_class, InvalidRequestURI)

    def test_signed_payload_must_be_a_json_object(self):
        for payload in [b"not json", b"[1, 2]"]:
            with self.subTest(payload=payload):
                token = jws.JWS(payload)
                token.add_signature(CLIENT_KEY, alg="RS256", protected={"alg": "RS256"})
                with self.assertRaises(RequestObjectError):
                    self.resolve(token.serialize(compact=True))

    def test_audience_without_an_oidc_issuer(self):
        # The RFC 8414 issuer still applies when the OIDC one cannot be derived.
        self.oauth2_settings.OIDC_ISS_ENDPOINT = ""
        with mock.patch.object(OAuth2ProviderSettings, "oidc_issuer", side_effect=RuntimeError):
            self.assertEqual(self.resolve(signed({"aud": "http://testserver/o"})), self.OUTER)

    def test_audience_is_checked_against_the_derived_issuer(self):
        self.oauth2_settings.OIDC_ISS_ENDPOINT = ""
        claims = {"aud": "http://testserver/o"}
        self.assertEqual(self.resolve(signed(claims)), self.OUTER)
        with self.assertRaises(RequestObjectError):
            self.resolve(signed({"aud": "http://elsewhere.example/o"}))


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_REQUEST_OBJECTS)
class TestSafeRequestURIFetcher(TestCase):
    def test_fetch_uses_safe_fetch(self):
        self.oauth2_settings.OIDC_REQUEST_URI_FETCH_TIMEOUT_SECONDS = 3
        with mock.patch.object(safe_fetch, "fetch_https_document", return_value="x.y.") as fetch:
            self.assertEqual(SafeRequestURIFetcher().fetch(REQUEST_URI), "x.y.")
        _args, kwargs = fetch.call_args
        self.assertEqual(fetch.call_args.args, (REQUEST_URI,))
        self.assertEqual(kwargs["timeout"], 3)
        self.assertIs(kwargs["exc_class"], RequestURIFetchError)
        self.assertTrue(kwargs["accept"].startswith("application/oauth-authz-req+jwt"))

    def test_internal_addresses_are_refused(self):
        with mock.patch.object(
            safe_fetch.socket, "getaddrinfo", return_value=[(None, None, None, None, ("10.0.0.1", 443))]
        ):
            with self.assertRaises(RequestURIFetchError):
                SafeRequestURIFetcher().fetch(REQUEST_URI)

    def test_non_https_is_refused(self):
        with self.assertRaises(RequestURIFetchError):
            SafeRequestURIFetcher().fetch("http://client.example/request.jwt")

    def test_read_document(self):
        self.oauth2_settings.OIDC_REQUEST_URI_MAX_SIZE = 8

        def response(status, body):
            return mock.Mock(status=status, read=lambda size: body[:size])

        self.assertEqual(SafeRequestURIFetcher._read_document(response(200, b" a.b.c\n")), "a.b.c")
        for status, body in [(404, b"a.b."), (200, b"a.b.c.d.e.f"), (200, "é".encode())]:
            with self.subTest(status=status, body=body):
                with self.assertRaises(RequestURIFetchError):
                    SafeRequestURIFetcher._read_document(response(status, body))


@pytest.mark.parametrize(
    "path", ["oauth2_provider:oidc-connect-discovery-info", "oauth2_provider:oauth-server-metadata"]
)
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_REQUEST_OBJECTS)
def test_discovery_advertises_request_objects(oauth2_settings, client, path):
    oauth2_settings.OIDC_REQUEST_OBJECT_SIGNING_ALGS = ["none", "RS256"]
    data = client.get(reverse(path)).json()
    assert data["request_parameter_supported"] is True
    assert data["request_uri_parameter_supported"] is True
    assert data["require_request_uri_registration"] is False
    assert data["request_object_signing_alg_values_supported"] == ["none", "RS256"]


@pytest.mark.parametrize(
    "path", ["oauth2_provider:oidc-connect-discovery-info", "oauth2_provider:oauth-server-metadata"]
)
@pytest.mark.oauth2_settings(presets.OIDC_SETTINGS_RW)
def test_discovery_without_request_objects(oauth2_settings, client, path):
    data = client.get(reverse(path)).json()
    assert data["request_parameter_supported"] is False
    assert data["request_uri_parameter_supported"] is False
    assert "require_request_uri_registration" not in data
    assert "request_object_signing_alg_values_supported" not in data
