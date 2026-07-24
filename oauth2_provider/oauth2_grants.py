"""
Custom oauthlib grant-type handlers authored in django-oauth-toolkit.

oauthlib (as of 3.3.x) ships no server-side handler for the RFC 7523 §2.1 JWT
bearer authorization grant — only the client-side
``oauthlib.oauth2.rfc6749.clients.service_application`` — so the handler lives
here and is registered on the DOT server subclasses in
:mod:`oauth2_provider.oauth2_servers`.

:class:`JWTBearerGrant` is deliberately written against the oauthlib grant
interface alone (its only DOT dependency is the grant-type URN constant): every
JWT-specific operation is delegated to the request validator's
``validate_jwt_bearer_assertion`` hook, so the class stays a candidate for
upstreaming into oauthlib unchanged.
"""

import json
import logging

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types.base import GrantTypeBase


log = logging.getLogger(__name__)

# RFC 7523 §2.1 grant-type identifier used at the token endpoint.
JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class JWTBearerGrant(GrantTypeBase):
    """RFC 7523 §2.1 JWT bearer authorization grant.

    A client presents a signed JWT ``assertion`` at the token endpoint and, if
    the assertion is trusted and maps to a resource owner, receives an access
    token. Client authentication is optional per RFC 7521 §4.1, but the client
    must still be *identifiable* (via ``client_id`` or client credentials) so
    the authorization server can gate the grant per registered application.

    All assertion handling — signature verification, RFC 7523 §3 claim
    validation, replay detection and subject→user resolution — is performed by
    ``request_validator.validate_jwt_bearer_assertion(request)``, which must set
    ``request.user`` on success and raise an ``OAuth2Error`` (or return a falsy
    value) on failure.
    """

    def create_token_response(self, request, token_handler):
        """Validate the assertion and return a token (or error) as JSON."""
        headers = self._get_default_headers()
        try:
            log.debug("Validating JWT bearer token request, %r.", request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug("Client error in JWT bearer token request. %s.", e)
            headers.update(e.headers)
            return headers, e.json, e.status_code

        # RFC 7523 assertions are the client's long-lived credential, so a
        # refresh token is not issued unless explicitly enabled by the caller.
        token = token_handler.create_token(request, refresh_token=self.refresh_token)

        for modifier in self._token_modifiers:
            token = modifier(token)

        self.request_validator.save_token(token, request)

        log.debug("Issuing token to client id %r (%r), %r.", request.client_id, request.client, token)
        return headers, json.dumps(token), 200

    def validate_token_request(self, request):
        """Validate an RFC 7523 §2.1 token request."""
        for validator in self.custom_validators.pre_token:
            validator(request)

        if not getattr(request, "grant_type", None):
            raise errors.InvalidRequestError("Request is missing grant type.", request=request)

        if request.grant_type != JWT_BEARER_GRANT_TYPE:
            raise errors.UnsupportedGrantTypeError(request=request)

        if not getattr(request, "assertion", None):
            raise errors.InvalidRequestError("Request is missing assertion parameter.", request=request)

        for param in ("grant_type", "scope", "assertion"):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(
                    description="Duplicate %s parameter." % param, request=request
                )

        # Identify the client. RFC 7521 §4.1 makes client authentication
        # optional for the assertion grant, but DOT still requires the client to
        # be identifiable so the grant can be authorized per application.
        log.debug("Identifying client, %r.", request)
        if self.request_validator.client_authentication_required(request):
            if not self.request_validator.authenticate_client(request):
                log.debug("Client authentication failed, %r.", request)
                raise errors.InvalidClientError(request=request)
        elif not self.request_validator.authenticate_client_id(request.client_id, request):
            log.debug("Client authentication failed, %r.", request)
            raise errors.InvalidClientError(request=request)

        if not hasattr(request.client, "client_id"):
            raise NotImplementedError(
                "Authenticate client must set the request.client.client_id attribute in authenticate_client."
            )

        request.client_id = request.client_id or request.client.client_id

        # Ensure the identified client is authorized to use this grant type.
        self.validate_grant_type(request)

        # Verify the assertion (signature, RFC 7523 §3 claims, replay) and map
        # its subject to a resource owner. The validator sets request.user.
        log.debug("Validating JWT bearer assertion for client %r.", request.client_id)
        if not self.request_validator.validate_jwt_bearer_assertion(request):
            raise errors.InvalidGrantError(description="Assertion is not valid.", request=request)

        self.validate_scopes(request)

        for validator in self.custom_validators.post_token:
            validator(request)
