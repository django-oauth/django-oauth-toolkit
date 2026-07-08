"""
A Python relying-party / OAuth client that drives the live IdP end-to-end over
HTTP the way a real client (and its user's browser) would: it fetches and
submits the IdP's actual login, consent, and device-approval HTML forms, and
calls the token / introspection / revocation / userinfo / device endpoints
directly.

Method names and docstrings use OAuth 2.0 / OIDC specification vocabulary so the
spec test modules read as compliance statements.
"""

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlparse

import requests

from .http_forms import parse_form


def generate_pkce_pair():
    """Return ``(code_verifier, code_challenge)`` for the S256 method (RFC 7636 §4)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class AuthorizeResult:
    """The outcome of an authorization request (RFC 6749 §4.1.2 / §4.2.2)."""

    def __init__(self, response):
        self.response = response
        self.status_code = response.status_code
        self.location = response.headers.get("Location")

    @property
    def query_params(self):
        if not self.location:
            return {}
        return {k: v[0] for k, v in parse_qs(urlparse(self.location).query).items()}

    @property
    def fragment_params(self):
        if not self.location:
            return {}
        return {k: v[0] for k, v in parse_qs(urlparse(self.location).fragment).items()}

    @property
    def params(self):
        merged = dict(self.query_params)
        merged.update(self.fragment_params)
        return merged

    def __repr__(self):
        return f"<AuthorizeResult {self.status_code} location={self.location!r}>"


class OAuthClient:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.issuer = f"{self.base_url}/o"

    def url(self, path):
        return f"{self.base_url}{path}"

    # --- Discovery / metadata ---------------------------------------------
    def discovery(self):
        """OIDC Discovery 1.0 provider configuration."""
        return requests.get(f"{self.issuer}/.well-known/openid-configuration", timeout=5)

    def oauth_metadata(self):
        """RFC 8414 Authorization Server Metadata.

        Prefers the spec-strict well-known location for an issuer that has a path
        component (issuer ``.../o`` -> ``/.well-known/oauth-authorization-server/o``),
        falling back to the issuer-prefixed form some deployments expose.
        """
        strict = requests.get(self.url("/.well-known/oauth-authorization-server/o"), timeout=5)
        if strict.status_code == 200:
            return strict
        return requests.get(self.url("/o/.well-known/oauth-authorization-server"), timeout=5)

    def jwks(self):
        return requests.get(f"{self.issuer}/.well-known/jwks.json", timeout=5)

    # --- Resource-owner user agent (login + consent) ----------------------
    def _csrf_get(self, session, url, **kwargs):
        return session.get(url, allow_redirects=False, **kwargs)

    def login(self, username, password, session=None):
        """Authenticate the resource owner through the IdP's login page.

        Returns an authenticated ``requests.Session`` (cookie jar carries the
        session + CSRF cookies).
        """
        session = session or requests.Session()
        login_url = self.url("/accounts/login/")
        resp = self._csrf_get(session, login_url)
        _, fields = parse_form(resp.text)
        fields["username"] = username
        fields["password"] = password
        resp = session.post(login_url, data=fields, allow_redirects=False)
        if resp.status_code not in (301, 302):
            raise AssertionError(f"Login did not succeed (status {resp.status_code})")
        return session

    def authorize(
        self,
        session,
        *,
        client_id,
        response_type,
        redirect_uri=None,
        scope=None,
        state=None,
        nonce=None,
        code_challenge=None,
        code_challenge_method=None,
        claims=None,
        extra=None,
        approve=True,
    ):
        """Make an authorization request (RFC 6749 §4.1.1 / §4.2.1).

        Completes the consent screen when the client is not configured with
        ``skip_authorization``. ``approve=False`` denies consent. Never follows
        the final redirect, so the authorization response is read straight off
        the ``Location`` header.
        """
        params = {"client_id": client_id, "response_type": response_type}
        if redirect_uri is not None:
            params["redirect_uri"] = redirect_uri
        if scope is not None:
            params["scope"] = scope
        if state is not None:
            params["state"] = state
        if nonce is not None:
            params["nonce"] = nonce
        if code_challenge is not None:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method or "S256"
        if claims is not None:
            params["claims"] = claims
        if extra:
            params.update(extra)

        resp = session.get(self.url("/o/authorize/"), params=params, allow_redirects=False)
        if resp.status_code == 200 and "<form" in resp.text:
            # Consent screen. Resubmit the hidden fields, approving or denying.
            action, fields = parse_form(resp.text)
            if approve:
                fields["allow"] = "Authorize"
            else:
                fields.pop("allow", None)
            post_url = action or self.url("/o/authorize/")
            resp = session.post(post_url, data=fields, allow_redirects=False)
        return AuthorizeResult(resp)

    # --- Token endpoint ----------------------------------------------------
    def token(self, data):
        """Raw POST to the token endpoint (RFC 6749 §3.2)."""
        return requests.post(self.url("/o/token/"), data=data, timeout=10)

    def exchange_code(self, *, client_id, code, redirect_uri, code_verifier=None, client_secret=None):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }
        if code_verifier is not None:
            data["code_verifier"] = code_verifier
        if client_secret is not None:
            data["client_secret"] = client_secret
        return self.token(data)

    def client_credentials(self, *, client_id, client_secret, scope=None):
        data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
        if scope is not None:
            data["scope"] = scope
        return self.token(data)

    def password_grant(self, *, client_id, client_secret, username, password, scope=None):
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope is not None:
            data["scope"] = scope
        return self.token(data)

    def refresh(self, *, client_id, refresh_token, client_secret=None, scope=None):
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
        if client_secret is not None:
            data["client_secret"] = client_secret
        if scope is not None:
            data["scope"] = scope
        return self.token(data)

    # --- Revocation (RFC 7009) / Introspection (RFC 7662) -----------------
    def revoke(self, *, token, client_id, client_secret=None, token_type_hint=None):
        data = {"token": token, "client_id": client_id}
        if client_secret is not None:
            data["client_secret"] = client_secret
        if token_type_hint is not None:
            data["token_type_hint"] = token_type_hint
        return requests.post(self.url("/o/revoke_token/"), data=data, timeout=10)

    def introspect(self, *, token, bearer, token_type_hint=None):
        """Introspect ``token`` using an access token that carries the
        ``introspection`` scope as the caller's bearer credential."""
        data = {"token": token}
        if token_type_hint is not None:
            data["token_type_hint"] = token_type_hint
        headers = {"Authorization": f"Bearer {bearer}"}
        return requests.post(self.url("/o/introspect/"), data=data, headers=headers, timeout=10)

    # --- OIDC UserInfo + RP-Initiated Logout ------------------------------
    def userinfo(self, access_token):
        headers = {"Authorization": f"Bearer {access_token}"}
        return requests.get(f"{self.issuer}/userinfo/", headers=headers, timeout=10)

    def rp_logout(
        self, session, *, id_token_hint=None, client_id=None, post_logout_redirect_uri=None, state=None
    ):
        """OIDC RP-Initiated Logout 1.0 (end_session)."""
        params = {}
        if id_token_hint is not None:
            params["id_token_hint"] = id_token_hint
        if client_id is not None:
            params["client_id"] = client_id
        if post_logout_redirect_uri is not None:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state is not None:
            params["state"] = state
        resp = session.get(self.url("/o/logout/"), params=params, allow_redirects=False)
        if resp.status_code == 200 and "<form" in resp.text:
            action, fields = parse_form(resp.text)
            fields["allow"] = "Authorize"
            resp = session.post(action or self.url("/o/logout/"), data=fields, allow_redirects=False)
        return resp

    # --- Device Authorization Grant (RFC 8628) ----------------------------
    def device_authorization(self, *, client_id, scope=None):
        data = {"client_id": client_id}
        if scope is not None:
            data["scope"] = scope
        return requests.post(self.url("/o/device-authorization/"), data=data, timeout=10)

    def device_user_approve(self, session, *, user_code, action="accept"):
        """Drive the user-interaction leg: enter the user code, then approve/deny.

        Requires an authenticated ``session`` (the verification pages are login
        protected).
        """
        device_url = self.url("/o/device/")
        resp = session.get(device_url, allow_redirects=False)
        _, fields = parse_form(resp.text)
        fields["user_code"] = user_code
        resp = session.post(device_url, data=fields, allow_redirects=False)
        confirm_url = resp.headers.get("Location")
        if not confirm_url:
            raise AssertionError(f"user_code submission did not redirect to confirm page: {resp.status_code}")
        if confirm_url.startswith("/"):
            confirm_url = self.url(confirm_url)
        resp = session.get(confirm_url, allow_redirects=False)
        _, fields = parse_form(resp.text)
        fields["action"] = action
        return session.post(confirm_url, data=fields, allow_redirects=False)

    def device_token(self, *, client_id, device_code):
        return self.token(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            }
        )


def get_csrf_token(session):
    """Return the CSRF cookie value from a session, if present."""
    for name in ("csrftoken", "csrf"):
        if name in session.cookies:
            return session.cookies[name]
    return None


BEARER_RE = re.compile(r'Bearer realm="[^"]*"')
