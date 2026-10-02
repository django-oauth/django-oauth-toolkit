"""The OpenID Provider's oauthlib server.

:class:`Server` is the default ``OIDC_SERVER_CLASS``. It is oauthlib's
``oauthlib.openid.Server`` with one change: the UserInfo response is shaped by
the validator's ``finalize_userinfo_response`` hook after the claims are
gathered, so the response can be a signed JWT (OpenID Connect Core 1.0 section
5.3.2) while ``get_userinfo_claims`` keeps returning the claims as a dict.
"""

import json
import logging
from typing import TYPE_CHECKING

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.endpoints.base import catch_errors_and_unavailability
from oauthlib.openid import Server as OpenIDServer

from oauth2_provider.settings import oauth2_settings


if TYPE_CHECKING:
    from oauth2_provider.models import AbstractApplication


log = logging.getLogger("oauth2_provider")


def userinfo_signing_available() -> bool:
    """Return whether this OpenID Provider signs UserInfo responses for clients that ask.

    Signing (OpenID Connect Core 1.0 section 5.3.2) needs OpenID Connect enabled, an
    ``OIDC_RSA_PRIVATE_KEY``, a server class derived from :class:`Server` and a
    validator with a callable ``finalize_userinfo_response``. Discovery advertises
    ``userinfo_signing_alg_values_supported`` and registration accepts
    ``userinfo_signed_response_alg`` only when this holds, so a client is never
    promised a signed response the endpoint would send as JSON.
    """
    if not (oauth2_settings.OIDC_ENABLED and oauth2_settings.OIDC_RSA_PRIVATE_KEY):
        return False
    try:
        server_class = oauth2_settings.OAUTH2_SERVER_CLASS
        validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    except ImportError:
        return False
    return (
        isinstance(server_class, type)
        and issubclass(server_class, Server)
        and callable(getattr(validator_class, "finalize_userinfo_response", None))
    )


def signs_userinfo_for(application: "AbstractApplication") -> bool:
    """Return whether the UserInfo response for *application* is a signed JWT.

    The single test both the UserInfo endpoint (``finalize_userinfo_response``) and
    registration responses use, so a client is told exactly what it will receive: the
    application asked for RS256, it supports OpenID Connect (it has an ID Token
    ``algorithm``), and :func:`userinfo_signing_available` holds.
    """
    # The algorithm constants are read from the instance so this module does not import
    # the models, which settings resolution could otherwise reach before apps are ready.
    return (
        application.userinfo_signed_response_alg == application.RS256_ALGORITHM
        and application.algorithm != application.NO_ALGORITHM
        and userinfo_signing_available()
    )


class Server(OpenIDServer):
    """oauthlib's OpenID Connect server with signed UserInfo responses."""

    @catch_errors_and_unavailability
    def create_userinfo_response(
        self, uri: str, http_method: str = "GET", body: str | None = None, headers: dict | None = None
    ) -> tuple[dict, str, int]:
        """Validate the bearer token and return the UserInfo response.

        Follows oauthlib's ``UserInfoEndpoint.create_userinfo_response``, then
        hands the claims to ``request_validator.finalize_userinfo_response``.
        A dict it returns is sent as ``application/json``, a string (a signed
        JWT) as ``application/jwt`` (OpenID Connect Core 1.0 section 5.3.2).
        """
        request = Request(uri, http_method, body, headers)
        request.scopes = ["openid"]
        self.validate_userinfo_request(request)

        claims = self.request_validator.get_userinfo_claims(request)
        if claims is None:
            log.error("Userinfo MUST have claims for %r.", request)
            raise errors.ServerError(status_code=500)
        if isinstance(claims, dict):
            self._ensure_sub(claims, request)
            # A validator without a callable hook (one that is not an OAuth2Validator,
            # or that sets it to None) keeps oauthlib's behaviour of returning JSON;
            # userinfo_signing_available() then reports signing as unavailable.
            finalize = getattr(self.request_validator, "finalize_userinfo_response", None)
            if callable(finalize):
                claims = finalize(claims, request)

        if isinstance(claims, dict):
            # Checked again: a finalize_userinfo_response override may have dropped it.
            self._ensure_sub(claims, request)
            return {"Content-Type": "application/json"}, json.dumps(claims), 200
        if isinstance(claims, str):
            return {"Content-Type": "application/jwt"}, claims, 200
        log.error("Userinfo return unknown response for %r.", request)
        raise errors.ServerError(status_code=500)

    @staticmethod
    def _ensure_sub(claims: dict, request: Request) -> None:
        # OpenID Connect Core 1.0 section 5.3.2: the sub Claim MUST always be returned.
        if "sub" not in claims:
            log.error('Userinfo MUST have "sub" for %r.', request)
            raise errors.ServerError(status_code=500)
