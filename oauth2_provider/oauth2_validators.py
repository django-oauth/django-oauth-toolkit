import base64
import binascii
import hashlib
import inspect
import json
import logging
import uuid
from collections import OrderedDict
from datetime import timedelta
from datetime import timezone as datetime_timezone
from urllib.parse import unquote_plus

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import check_password, identify_hasher
from django.db import IntegrityError, router, transaction
from django.http import HttpRequest
from django.utils import dateformat, timezone
from django.utils.crypto import constant_time_compare
from django.utils.timezone import make_aware
from django.utils.translation import gettext_lazy as _
from jwcrypto import jws, jwt
from jwcrypto.common import JWException
from jwcrypto.jwt import JWTExpired
from oauthlib.common import Request as OauthlibRequest
from oauthlib.oauth2.rfc6749 import errors, utils
from oauthlib.openid import RequestValidator

from .authorization_server import cimd, client_assertions
from .core.bcp import bcp_compliant
from .core.exceptions import FatalClientError
from .core.scopes import get_scopes_backend
from .models import (
    AbstractAccessToken,
    AbstractApplication,
    AbstractRefreshToken,
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
    refresh_token_expire_timedelta,
    revoke_access_token,
    set_token_value,
)

# Re-exported for backward compatibility: these RFC 8707 helpers used to live in
# this module and were part of its public API (e.g. the historical
# RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR default pointed here). They now live in
# oauth2_provider.resource_server.validators; keep the old import path working.
from .resource_server.validators import (
    _SCHEME_DEFAULT_PORTS,  # noqa: F401
    ResourceServerValidatorMixin,
    _parse_and_validate_uri,
    is_valid_resource_uri,
    validate_resource_as_url_prefix,
)
from .settings import oauth2_settings


# Public API of this module. ``is_valid_resource_uri`` and
# ``validate_resource_as_url_prefix`` are re-exported from
# ``resource_server.validators`` for backward compatibility (listing them here
# also marks the re-export imports above as intentional public API).
__all__ = [
    "OAuth2Validator",
    "GRANT_TYPE_MAPPING",
    "is_valid_resource_uri",
    "validate_resource_as_url_prefix",
]


log = logging.getLogger("oauth2_provider")

GRANT_TYPE_MAPPING = {
    "authorization_code": (
        AbstractApplication.GRANT_AUTHORIZATION_CODE,
        AbstractApplication.GRANT_OPENID_HYBRID,
    ),
    "password": (AbstractApplication.GRANT_PASSWORD,),
    "client_credentials": (AbstractApplication.GRANT_CLIENT_CREDENTIALS,),
    "refresh_token": (
        AbstractApplication.GRANT_AUTHORIZATION_CODE,
        AbstractApplication.GRANT_DEVICE_CODE,
        AbstractApplication.GRANT_PASSWORD,
        AbstractApplication.GRANT_CLIENT_CREDENTIALS,
        AbstractApplication.GRANT_OPENID_HYBRID,
    ),
    "urn:ietf:params:oauth:grant-type:device_code": (AbstractApplication.GRANT_DEVICE_CODE,),
}

Application = get_application_model()
AccessToken = get_access_token_model()
IDToken = get_id_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()


class OAuth2Validator(ResourceServerValidatorMixin, RequestValidator):
    # Return the given claim only if the given scope is present.
    # Extended as needed for non-standard OIDC claims/scopes.
    # Override by setting to None to ignore scopes.
    # see https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
    # For example, for the "nickname" claim, you need the "profile" scope.
    oidc_claim_scope = {
        "sub": "openid",
        "name": "profile",
        "family_name": "profile",
        "given_name": "profile",
        "middle_name": "profile",
        "nickname": "profile",
        "preferred_username": "profile",
        "profile": "profile",
        "picture": "profile",
        "website": "profile",
        "gender": "profile",
        "birthdate": "profile",
        "zoneinfo": "profile",
        "locale": "profile",
        "updated_at": "profile",
        "email": "email",
        "email_verified": "email",
        "address": "address",
        "phone_number": "phone",
        "phone_number_verified": "phone",
    }

    def _extract_basic_auth(self, request):
        """
        Return authentication string if request contains basic auth credentials,
        otherwise return None
        """
        auth = request.headers.get("HTTP_AUTHORIZATION", None)
        if not auth:
            return None

        split = auth.split(" ", 1)
        if len(split) != 2:
            return None
        auth_type, auth_string = split

        if auth_type != "Basic":
            return None

        return auth_string

    def _check_secret(self, provided_secret, stored_secret):
        """
        Checks whether the provided client secret is valid.

        Supports both hashed and unhashed secrets.
        """
        try:
            identify_hasher(stored_secret)
            return check_password(provided_secret, stored_secret)
        except ValueError:  # Raised if the stored_secret is not hashed.
            return constant_time_compare(provided_secret, stored_secret)

    def _authenticate_basic_auth(self, request):
        """
        Authenticates with HTTP Basic Auth.

        Note: as stated in rfc:`2.3.1`, client_id and client_secret must be encoded with
        "application/x-www-form-urlencoded" encoding algorithm.
        """
        auth_string = self._extract_basic_auth(request)
        if not auth_string:
            return False

        try:
            encoding = request.encoding or settings.DEFAULT_CHARSET or "utf-8"
        except AttributeError:
            encoding = "utf-8"

        try:
            b64_decoded = base64.b64decode(auth_string)
        except (TypeError, binascii.Error):
            # auth_string is the base64 of "client_id:client_secret"; never log it.
            log.debug("Failed basic auth: credentials can't be decoded as base64")
            return False

        try:
            auth_string_decoded = b64_decoded.decode(encoding)
        except UnicodeDecodeError:
            # auth_string is the base64 of "client_id:client_secret"; never log it.
            log.debug("Failed basic auth: credentials can't be decoded as unicode by %r", encoding)
            return False

        try:
            client_id, client_secret = map(unquote_plus, auth_string_decoded.split(":", 1))
        except ValueError:
            log.debug("Failed basic auth, Invalid base64 encoding.")
            return False

        if self._load_application(client_id, request) is None:
            log.debug("Failed basic auth: Application %s does not exist" % client_id)
            return False
        elif request.client.client_id != client_id:
            log.debug("Failed basic auth: wrong client id %s" % client_id)
            return False
        elif request.client.token_endpoint_auth_method in AbstractApplication.JWT_AUTH_METHODS:
            # RFC 9700 section 2.5: a client registered for JWT client
            # authentication (RFC 7523) must use it; a leaked secret must not
            # open a weaker side door.
            # request.client.client_id (from the loaded Application) rather than
            # the credential-derived client_id, so nothing tainted by the
            # Authorization header reaches the log.
            log.debug(
                "Failed basic auth: client %s is registered for %s and must use a client assertion",
                request.client.client_id,
                request.client.token_endpoint_auth_method,
            )
            return False
        elif (
            request.client.client_type == "public"
            and request.grant_type == "urn:ietf:params:oauth:grant-type:device_code"
        ):
            return True
        elif not self._check_secret(client_secret, request.client.client_secret):
            log.debug("Failed basic auth: wrong client secret for client_id %s", client_id)
            return False
        else:
            return True

    def _authenticate_request_body(self, request):
        """
        Try to authenticate the client using client_id and client_secret
        parameters included in body.

        Remember that this method is NOT RECOMMENDED and SHOULD be limited to
        clients unable to directly utilize the HTTP Basic authentication scheme.
        See rfc:`2.3.1` for more details.
        """
        # TODO: check if oauthlib has already unquoted client_id and client_secret
        try:
            client_id = request.client_id
            client_secret = getattr(request, "client_secret", "") or ""
        except AttributeError:
            return False

        if self._load_application(client_id, request) is None:
            log.debug("Failed body auth: Application %s does not exists" % client_id)
            return False
        elif request.client.token_endpoint_auth_method in AbstractApplication.JWT_AUTH_METHODS:
            # See _authenticate_basic_auth: JWT-registered clients may only
            # authenticate with a client assertion.
            log.debug(
                "Failed body auth: client %s is registered for %s and must use a client assertion",
                request.client.client_id,
                request.client.token_endpoint_auth_method,
            )
            return False
        elif (
            request.client.client_type == "public"
            and request.grant_type == "urn:ietf:params:oauth:grant-type:device_code"
        ):
            return True
        elif not self._check_secret(client_secret, request.client.client_secret):
            log.debug("Failed body auth: wrong client secret for client_id %s", client_id)
            return False
        else:
            return True

    def _load_application(self, client_id, request):
        """
        If request.client was not set, load application instance for given
        client_id and store it in request.client

        When CIMD is enabled and client_id is a metadata-document URL, this may
        additionally fetch that URL and persist an Application on first sight (or
        re-fetch a stale one), so a lookup here can perform network I/O and a
        write to the default database.
        """
        if request.client:
            # check for cached client, to save the db hit if this has already been loaded
            if not isinstance(request.client, Application):
                # resetting request.client (client_id=%r):
                # not an Application, something else set request.client erroneously
                request.client = None
            elif request.client.client_id != client_id:
                # resetting request.client (client_id=%r):
                # request.client.client_id does not match the given client_id
                request.client = None
            elif not request.client.is_usable(request):
                # resetting request.client (client_id=%r):
                # request.client is a valid Application, but is not usable
                request.client = None
            else:
                # request.client is a valid Application, reusing it
                return request.client
        try:
            # cache not hit, loading application from database for client_id %r
            client = Application.objects.get(client_id=client_id)
        except Application.DoesNotExist:
            # Not stored yet: the client_id may be a Client ID Metadata Document
            # URL we can fetch and persist on first sight. Returns None when CIMD
            # is disabled or the id is not a resolvable CIMD URL.
            client = cimd.resolve_cimd_application(client_id, request=request)
            if client is not None and client.is_usable(request):
                request.client = client
                return request.client
            return None
        except ValueError:
            # Some database backends (e.g. PostgreSQL via psycopg2)
            # raise ValueError instead of executing the query at all
            # when client_id contains characters they can't represent
            # in a string literal (most notably a NUL/0x00 byte). No
            # legitimate client_id could ever contain such a byte, so
            # treat this the same as "no matching Application found"
            # rather than letting it propagate into a 500 error.
            # See GH #1006.
            return None
        client = cimd.refresh_if_stale(client, request=request)
        if not client.is_usable(request):
            # Failed to load application: Application %r is not usable
            return None
        request.client = client
        # Loaded application with client_id %r from database
        return request.client

    def _set_oauth2_error_on_request(self, request, access_token, scopes):
        if access_token is None:
            error = OrderedDict(
                [
                    ("error", "invalid_token"),
                    ("error_description", _("The access token is invalid.")),
                ]
            )
        elif access_token.is_expired():
            error = OrderedDict(
                [
                    ("error", "invalid_token"),
                    ("error_description", _("The access token has expired.")),
                ]
            )
        elif not access_token.allow_scopes(scopes):
            error = OrderedDict(
                [
                    ("error", "insufficient_scope"),
                    ("error_description", _("The access token is valid but does not have enough scope.")),
                ]
            )
        else:
            log.warning("OAuth2 access token is invalid for an unknown reason.")
            error = OrderedDict(
                [
                    ("error", "invalid_token"),
                ]
            )
        request.oauth2_error = error
        return request

    def client_authentication_required(self, request, *args, **kwargs):
        """
        Determine if the client has to be authenticated

        This method is called only for grant types that supports client authentication:
            * Authorization code grant
            * Resource owner password grant
            * Refresh token grant

        If the request contains authorization headers, always authenticate the client
        no matter the grant type.

        If the request does not contain authorization headers, proceed with authentication
        only if the client is of type `Confidential`.

        If something goes wrong, call oauthlib implementation of the method.
        """
        # An RFC 7523 client assertion is client authentication by definition.
        # Presence of either parameter counts (even empty), so a malformed or
        # partial assertion attempt fails closed in authenticate_client instead
        # of slipping through as an unauthenticated public-client request.
        if self._presents_client_assertion(request):
            return True

        if self._extract_basic_auth(request):
            return True

        try:
            if request.client_id and request.client_secret:
                return True
        except AttributeError:
            log.debug("Client ID or client secret not provided...")
            pass

        self._load_application(request.client_id, request)
        log.debug("Determining if client authentication is required for client %r", request.client)
        if request.client:
            return request.client.client_type == AbstractApplication.CLIENT_CONFIDENTIAL

        return super().client_authentication_required(request, *args, **kwargs)

    def authenticate_client(self, request, *args, **kwargs):
        """
        Check if client exists and is authenticating itself as in rfc:`3.2.1`

        First we try to authenticate with HTTP Basic Auth, and that is the PREFERRED
        authentication method.
        Whether this fails we support including the client credentials in the request-body,
        but this method is NOT RECOMMENDED and SHOULD be limited to clients unable to
        directly utilize the HTTP Basic authentication scheme.
        See rfc:`2.3.1` for more details.

        A request carrying an RFC 7523 JWT client assertion is authenticated by
        that assertion alone: per RFC 7521 section 4.2 there is deliberately no
        fallback to the secret-based methods when the assertion is invalid.
        """
        if self._presents_client_assertion(request):
            return self._authenticate_client_assertion(request)

        authenticated = self._authenticate_basic_auth(request)

        if not authenticated:
            authenticated = self._authenticate_request_body(request)

        return authenticated

    @staticmethod
    def _presents_client_assertion(request):
        """True when the request carries either RFC 7523 assertion parameter,
        even with an empty value (oauthlib maps absent parameters to None)."""
        return (
            getattr(request, "client_assertion", None) is not None
            or getattr(request, "client_assertion_type", None) is not None
        )

    def _authenticate_client_assertion(self, request):
        """
        Authenticate a client presenting an RFC 7523 JWT client assertion
        (private_key_jwt / client_secret_jwt).

        Not related to the ``get_jwt_bearer_token`` / ``validate_jwt_bearer_token``
        methods below: despite the similar names, those are oauthlib's OpenID
        hooks treating the OIDC id_token as a bearer token, not RFC 7523.
        """
        return client_assertions.authenticate_client_assertion(request, self._load_application)

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """
        If we are here, the client did not authenticate itself as in rfc:`3.2.1` and we can
        proceed only if the client exists and is not of type "Confidential".
        """
        if self._load_application(client_id, request) is not None:
            return request.client.client_type != AbstractApplication.CLIENT_CONFIDENTIAL
        return False

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        """
        Ensure the redirect_uri is listed in the Application instance redirect_uris field
        """
        grant = Grant.objects.get(code=code, application=client)
        return grant.redirect_uri_allowed(redirect_uri)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        Remove the temporary grant used to swap the authorization token.

        :raises: InvalidGrantError if the grant does not exist.
        """
        deleted_grant_count, _ = Grant.objects.filter(code=code, application=request.client).delete()
        if not deleted_grant_count:
            raise errors.InvalidGrantError(request=request)

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        Ensure an Application exists with given client_id.
        If it exists, it's assigned to request.client.
        """
        return self._load_application(client_id, request) is not None

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return request.client.default_redirect_uri

    def get_or_create_user_from_content(self, content):
        """
        An optional layer to define where to store the profile in `UserModel` or a separate model.
        For example `UserOAuth`, where `user = models.OneToOneField(UserModel)` .

        The function is called after checking that username is in the content.

        Returns an UserModel instance;
        """
        user, _ = UserModel.objects.get_or_create(**{UserModel.USERNAME_FIELD: content["username"]})
        return user

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        try:
            grant = Grant.objects.get(code=code, application=client)
            if not grant.is_expired():
                request.scopes = grant.scope.split(" ")
                request.user = grant.user
                if grant.nonce:
                    request.nonce = grant.nonce
                if grant.claims:
                    request.claims = json.loads(grant.claims)
                return True
            return False

        except Grant.DoesNotExist:
            return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        """
        Validate both grant_type is a valid string and grant_type is allowed for current workflow
        """
        assert grant_type in GRANT_TYPE_MAPPING  # mapping misconfiguration
        allowed = request.client.allows_grant_type(*GRANT_TYPE_MAPPING[grant_type])
        # RFC 9700 §2.4: the resource owner password credentials grant MUST NOT be
        # used. The gate is only consulted (and thus only warns) when the client is
        # otherwise allowed to use the grant, so requests that are rejected anyway
        # don't emit the deprecation warning.
        if (
            allowed
            and grant_type == "password"
            and bcp_compliant(
                "COMPLIANT_BCP_RFC9700_PASSWORD_GRANT",
                "The OAuth 2.0 resource owner password credentials grant",
            )
        ):
            return False
        return allowed

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """
        We currently do not support the Authorization Endpoint Response Types registry as in
        rfc:`8.4`, so validate the response_type only if it matches "code" or "token"
        """
        if response_type == "code":
            return client.allows_grant_type(AbstractApplication.GRANT_AUTHORIZATION_CODE)
        elif response_type == "token":
            return self._validate_implicit_response_type(client)
        elif response_type == "id_token":
            return self._validate_implicit_response_type(client)
        elif response_type == "id_token token":
            return self._validate_implicit_response_type(client)
        elif response_type == "code id_token":
            return client.allows_grant_type(AbstractApplication.GRANT_OPENID_HYBRID)
        elif response_type == "code token":
            return client.allows_grant_type(AbstractApplication.GRANT_OPENID_HYBRID)
        elif response_type == "code id_token token":
            return client.allows_grant_type(AbstractApplication.GRANT_OPENID_HYBRID)
        else:
            return False

    def _validate_implicit_response_type(self, client):
        """
        Validate an implicit-grant response type (``token``/``id_token``).

        RFC 9700 §2.1.2 says the implicit grant MUST NOT be used. Gated by
        COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT: when the gate is enabled the
        response type is rejected even for applications registered for it.
        """
        if not client.allows_grant_type(AbstractApplication.GRANT_IMPLICIT):
            return False
        if bcp_compliant(
            "COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT",
            "The OAuth 2.0 implicit grant (response_type=token/id_token)",
        ):
            return False
        return True

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """
        Ensure required scopes are permitted (as specified in the settings file)
        """
        available_scopes = get_scopes_backend().get_available_scopes(application=client, request=request)
        return set(scopes).issubset(set(available_scopes))

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        default_scopes = get_scopes_backend().get_default_scopes(application=request.client, request=request)
        return default_scopes

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return request.client.redirect_uri_allowed(redirect_uri)

    def is_pkce_required(self, client_id, request):
        """
        Enables or disables PKCE verification.

        Uses the setting PKCE_REQUIRED, which can be either a bool or a callable that
        receives the client id and returns a bool.
        """
        if callable(oauth2_settings.PKCE_REQUIRED):
            return oauth2_settings.PKCE_REQUIRED(client_id)
        return oauth2_settings.PKCE_REQUIRED

    def get_code_challenge(self, code, request):
        grant = Grant.objects.get(code=code, application=request.client)
        return grant.code_challenge or None

    def get_code_challenge_method(self, code, request):
        grant = Grant.objects.get(code=code, application=request.client)
        return grant.code_challenge_method or None

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        self._create_authorization_code(request, code)

    def get_authorization_code_scopes(self, client_id, code, redirect_uri, request):
        scopes = Grant.objects.filter(code=code).values_list("scope", flat=True).first()
        if scopes:
            return utils.scope_to_list(scopes)
        return []

    def rotate_refresh_token(self, request):
        """
        Checks if rotate refresh token is enabled
        """
        return oauth2_settings.ROTATE_REFRESH_TOKEN

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Save access and refresh token.

        Override _save_bearer_token and not this function when adding custom logic
        for the storing of these token. This allows the transaction logic to be
        separate from the token handling.
        """
        # Use the AccessToken's database instead of making the assumption it is in 'default'.
        with transaction.atomic(using=router.db_for_write(AccessToken)):
            return self._save_bearer_token(token, request, *args, **kwargs)

    def _validate_resource_uris(self, request, resources):
        """
        RFC 8707: Reject any resource that is not an absolute URI with a scheme
        and host (no userinfo or fragment). Note this is stricter than RFC 3986
        absolute-URI: authority-less forms such as URNs are rejected because the
        default prefix validator matches on (scheme, host, port, path).
        """
        for res in resources:
            if _parse_and_validate_uri(res) is None:
                raise errors.CustomOAuth2Error(
                    error="invalid_target",
                    description=(
                        f"The resource '{res}' is not a valid resource indicator: "
                        "it must be an absolute URI with a scheme and host."
                    ),
                    request=request,
                )

    def _check_and_set_request_resource(self, request):
        """
        Handle 'resource' parameter from token requests (RFC 8707).
        Normalizes request.resource to a list of URIs.

        request.resource will be set to one of:
        - [] (no resources)
        - List of URIs: ["https://api.example.com"] or ["https://a.com", "https://b.com"]
        """
        resource = getattr(request, "resource", None)

        # RFC 8707 allows repeating the ``resource`` parameter, but oauthlib
        # keeps only the last value when body parameters repeat. Recover the
        # full list from the decoded body.
        if isinstance(resource, str):
            body_values = [
                value for key, value in (getattr(request, "decoded_body", None) or []) if key == "resource"
            ]
            if len(body_values) > 1:
                resource = body_values

        if isinstance(resource, list):
            # Already a list, use as-is
            request.resource = resource or []
        elif resource and isinstance(resource, str) and resource.strip():
            # Single URI string from token endpoint POST
            request.resource = [resource]
        else:
            request.resource = []

        # RFC 8707: Validate that each resource is an absolute URI with scheme and host
        self._validate_resource_uris(request, request.resource)

        if request.grant_type == "authorization_code":
            # Handle grant resource narrowing
            grant = Grant.objects.filter(code=request.code, application=request.client).first()
            grant_resource = (grant.resource or []) if grant else []

            if request.resource and grant_resource:
                # Token request is narrowing the resource scope
                # Validate that requested resources are a subset of granted resources
                for res in request.resource:
                    if res not in grant_resource:
                        raise errors.CustomOAuth2Error(
                            error="invalid_target",
                            description=(
                                f"The requested resource '{res}' is not allowed. "
                                "Token request cannot escalate resource permissions beyond the "
                                "original authorization grant"
                            ),
                            request=request,
                        )
            elif grant_resource:
                # Inherited values may predate validation at the authorization
                # endpoint (e.g. rows written before upgrading) - validate them
                # before they end up on the issued token.
                self._validate_resource_uris(request, grant_resource)
                request.resource = grant_resource

        elif request.grant_type == "refresh_token":
            # Preserve resource from the refresh token
            refresh_token_instance = getattr(request, "refresh_token_instance", None)
            if refresh_token_instance and refresh_token_instance.resource:
                # If no resource specified in request, inherit from refresh token
                if not request.resource:
                    # Validate inherited values the same way as client-supplied ones.
                    self._validate_resource_uris(request, refresh_token_instance.resource)
                    request.resource = refresh_token_instance.resource
                # If resource specified, validate it's a subset of refresh token's resources
                elif request.resource != refresh_token_instance.resource:
                    refresh_list = refresh_token_instance.resource

                    for res in request.resource:
                        if res not in refresh_list:
                            raise errors.CustomOAuth2Error(
                                error="invalid_target",
                                description=(
                                    f"The requested resource '{res}' is not allowed. "
                                    "Token refresh cannot request resources beyond the "
                                    "original refresh token scope"
                                ),
                                request=request,
                            )

    def _save_bearer_token(self, token, request, *args, **kwargs):
        """
        Save access and refresh token.

        If refresh token is issued, remove or reuse old refresh token as in rfc:`6`.

        @see: https://rfc-editor.org/rfc/rfc6749.html#section-6
        """

        if "scope" not in token:
            raise FatalClientError("Failed to renew access token: missing scope")

        self._check_and_set_request_resource(request)

        # expires_in is passed to Server on initialization
        # custom server class can have logic to override this
        expires = timezone.now() + timedelta(
            seconds=token.get(
                "expires_in",
                oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            )
        )

        if request.grant_type == "client_credentials":
            request.user = None

        # This comes from OAuthLib:
        # https://github.com/idan/oauthlib/blob/1.0.3/oauthlib/oauth2/rfc6749/tokens.py#L267
        # Its value is either a new random code; or if we are reusing
        # refresh tokens, then it is the same value that the request passed in
        # (stored in `request.refresh_token`)
        refresh_token_code = token.get("refresh_token", None)

        if refresh_token_code:
            # an instance of `RefreshToken` that matches the old refresh code.
            # Set on the request in `validate_refresh_token`
            refresh_token_instance = getattr(request, "refresh_token_instance", None)

            # If we are to reuse tokens, and we can: do so
            if (
                not self.rotate_refresh_token(request)
                and isinstance(refresh_token_instance, RefreshToken)
                and refresh_token_instance.access_token
            ):
                access_token = AccessToken.objects.select_for_update().get(
                    pk=refresh_token_instance.access_token.pk
                )
                access_token.user = request.user
                access_token.scope = token["scope"]
                access_token.expires = expires
                self._set_token_value(access_token, token["access_token"])
                access_token.application = request.client
                access_token.resource = getattr(request, "resource", [])  # RFC 8707
                access_token.save()

            # else create fresh with access & refresh tokens
            else:
                # revoke existing tokens if possible to allow reuse of grant
                if isinstance(refresh_token_instance, RefreshToken):
                    # First, to ensure we don't have concurrency issues, we refresh the refresh token
                    # from the db while acquiring a lock on it
                    # We also put it in the "request cache"
                    refresh_token_instance = RefreshToken.objects.select_for_update().get(
                        pk=refresh_token_instance.pk
                    )
                    request.refresh_token_instance = refresh_token_instance

                    # Lock the previously issued access token too: a concurrent rotation
                    # may otherwise delete it (via ``AccessToken.revoke()``) between this
                    # lookup and re-issuing its refresh token below, which would turn the FK
                    # insert into an IntegrityError. Locking it holds it for this
                    # transaction; if it was already deleted, ``first()`` returns ``None`` and
                    # we fall through to minting a fresh pair (its OneToOne
                    # ``source_refresh_token`` slot is then free). This only ever waits on the
                    # access token, never on the other request's refresh token, so it cannot
                    # deadlock with the concurrent rotation (#1687).
                    previous_access_token = (
                        AccessToken.objects.select_for_update()
                        .filter(source_refresh_token=refresh_token_instance)
                        .first()
                    )
                    try:
                        refresh_token_instance.revoke()
                    except (AccessToken.DoesNotExist, RefreshToken.DoesNotExist):
                        pass
                    else:
                        setattr(request, "refresh_token_instance", None)
                else:
                    previous_access_token = None

                # If the refresh token has already been used to create an
                # access token (ie it's within the grace period), return that
                # access token
                if not previous_access_token:
                    access_token = self._create_access_token(
                        expires,
                        request,
                        token,
                        source_refresh_token=refresh_token_instance,
                    )

                    self._create_refresh_token(
                        request, refresh_token_code, access_token, refresh_token_instance
                    )
                else:
                    # make sure that the token data we're returning matches
                    # the existing token
                    existing_refresh_token = RefreshToken.objects.filter(
                        access_token=previous_access_token
                    ).first()
                    if existing_refresh_token is None:
                        # The refresh token bound to the previously issued access token was
                        # revoked/cleaned up (e.g. by ``clear_expired`` or a concurrent
                        # rotation) while the access token itself survived. Re-issue a
                        # refresh token for it instead of dereferencing ``None`` (#1687).
                        # Creating a fresh *access* token here would violate the OneToOne
                        # ``AccessToken.source_refresh_token`` constraint, since the surviving
                        # access token already occupies that relation.
                        existing_refresh_token = self._create_refresh_token(
                            request, refresh_token_code, previous_access_token, refresh_token_instance
                        )
                    token["access_token"] = previous_access_token.token
                    token["refresh_token"] = existing_refresh_token.token
                    token["scope"] = previous_access_token.scope

        # No refresh token should be created, just access token
        else:
            self._create_access_token(expires, request, token)

    def _set_token_value(
        self, token_instance: AbstractAccessToken | AbstractRefreshToken, raw_token: str
    ) -> None:
        """
        Assign the raw token to a token instance, honouring RFC 9700 token storage.

        See :func:`oauth2_provider.models.set_token_value`.
        """
        set_token_value(token_instance, raw_token)

    def _create_access_token(self, expires, request, token, source_refresh_token=None):
        id_token = token.get("id_token", None)
        if id_token:
            id_token = self._load_id_token(id_token)
        access_token = AccessToken(
            user=request.user,
            scope=token["scope"],
            expires=expires,
            id_token=id_token,
            application=request.client,
            source_refresh_token=source_refresh_token,
            resource=getattr(request, "resource", []),  # RFC 8707
        )
        self._set_token_value(access_token, token["access_token"])
        access_token.save()
        return access_token

    def _create_authorization_code(self, request, code, expires=None):
        if not expires:
            expires = timezone.now() + timedelta(seconds=oauth2_settings.AUTHORIZATION_CODE_EXPIRE_SECONDS)

        # RFC 9700 §2.1.1 / RFC 7636 §4.2: the "plain" PKCE code_challenge_method is
        # discouraged in favor of "S256". Gated by COMPLIANT_BCP_RFC9700_PKCE_METHOD.
        if request.code_challenge_method == "plain" and bcp_compliant(
            "COMPLIANT_BCP_RFC9700_PKCE_METHOD",
            'The PKCE "plain" code_challenge_method',
        ):
            raise errors.InvalidRequestError(
                description='Unsupported "plain" code_challenge_method; use "S256".',
                request=request,
            )

        # RFC 8707: Extract resource parameter
        resource = getattr(request, "resource", [])

        return Grant.objects.create(
            application=request.client,
            user=request.user,
            code=code["code"],
            expires=expires,
            redirect_uri=request.redirect_uri,
            scope=" ".join(request.scopes),
            code_challenge=request.code_challenge or "",
            code_challenge_method=request.code_challenge_method or "",
            nonce=request.nonce or "",
            claims=json.dumps(request.claims or {}),
            resource=resource,
        )

    def _create_refresh_token(self, request, refresh_token_code, access_token, previous_refresh_token):
        if previous_refresh_token:
            token_family = previous_refresh_token.token_family
        else:
            token_family = uuid.uuid4()
        refresh_token = RefreshToken(
            user=request.user,
            application=request.client,
            access_token=access_token,
            token_family=token_family,
            resource=getattr(request, "resource", []),  # RFC 8707
        )
        self._set_token_value(refresh_token, refresh_token_code)
        try:
            refresh_token.save()
        except IntegrityError as exc:
            # The row collided with one already stored -- in practice on the unique
            # ``token_checksum``, since rotation always mints a fresh value and a
            # non-rotating refresh leaves the existing row in place, so a duplicate points
            # at a REFRESH_TOKEN_GENERATOR that returns predictable or repeated values.
            # (The one-to-one ``access_token`` can also collide, if a concurrent rotation
            # claimed it between the lookup in ``_save_bearer_token`` and this insert.)
            #
            # Either way the grant cannot be completed, so fail it rather than letting the
            # IntegrityError surface as a 500: it propagates out of ``save_bearer_token``'s
            # atomic block, rolling it back, and ``OAuthLibCore.create_token_response``
            # renders it as an error response. Nothing is queried in between -- on
            # PostgreSQL the transaction is already poisoned and any query would raise
            # TransactionManagementError -- so the cause is reported, not narrowed.
            log.error(
                "Refusing to issue a refresh token: it collides with a token already "
                "stored (%s). If this recurs, check that REFRESH_TOKEN_GENERATOR returns "
                "unpredictable, unique values.",
                exc,
            )
            raise errors.InvalidGrantError(request=request) from exc
        return refresh_token

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """
        Revoke an access or refresh token.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: The HTTP Request (oauthlib.common.Request)
        """
        if token_type_hint not in ["access_token", "refresh_token"]:
            token_type_hint = None

        token_types = {
            "access_token": AccessToken,
            "refresh_token": RefreshToken,
        }

        token_checksum = hashlib.sha256(token.encode("utf-8")).hexdigest()
        token_type = token_types.get(token_type_hint, AccessToken)

        # RFC 7009 section 2.1: the authorization server "verifies whether the token was
        # issued to the client making the revocation request." A client must not be able
        # to revoke another client's tokens, so the lookup is scoped to the authenticated
        # client (request.client). Filtering by application in the queryset means a
        # same-checksum token belonging to a different client is treated like an unknown
        # token -- the search still falls back to the other token type, and the endpoint
        # returns 200 (RFC 7009 section 2.2) without disclosing whether the token exists.
        # Bail out when the request is not tied to a stored application so a NULL
        # application filter can never match unrelated tokens.
        application_pk = getattr(request.client, "pk", None)
        if application_pk is None:
            return

        # ``token_checksum`` is unique on both token models, so this matches at most one row.
        lookup = {"token_checksum": token_checksum, "application_id": application_pk}
        tokens = list(token_type.objects.filter(**lookup))
        if not tokens:
            for other_type in [_t for _t in token_types.values() if _t != token_type]:
                tokens.extend(other_type.objects.filter(**lookup))
        for t in tokens:
            if isinstance(t, AccessToken):
                # RFC 7009 section 2.1: revoking an access token MAY also revoke the bound
                # refresh token. We do -- otherwise deleting the access token alone leaves the
                # refresh token an active orphan (``RefreshToken.access_token`` is SET_NULL) that
                # can immediately re-mint an access token, defeating the revocation. ``revoke_access_token``
                # is the shared path used here, by ``AuthorizedTokenDeleteView``, and by the admin.
                revoke_access_token(t)
            else:
                t.revoke()

    def build_http_request(self, request: OauthlibRequest) -> HttpRequest:
        """
        Build a Django ``HttpRequest`` from the oauthlib ``Request`` for Django's
        ``authenticate()``. Override to pass extra attributes to your auth backends.
        """
        http_request = HttpRequest()
        http_request.path = request.uri
        http_request.method = request.http_method
        getattr(http_request, request.http_method).update(dict(request.decoded_body))
        http_request.META = request.headers
        return http_request

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        Check username and password correspond to a valid and active User
        """
        # Passing the optional HttpRequest adds compatibility for backends
        # which depend on its presence.
        http_request = self.build_http_request(request)
        u = None
        try:
            u = authenticate(http_request, username=username, password=password)
        except ValueError:
            # Some database backends (e.g. PostgreSQL via psycopg2)
            # raise ValueError instead of executing the underlying
            # user lookup query at all when username contains a NUL/0x00
            # byte, rather than the usual "no matching user" outcome
            # authenticate() otherwise returns as None. No legitimate
            # username can contain a NUL byte, so treat it the same way:
            # authentication simply failed, rather than letting it
            # propagate into a 500 error. Any other ValueError (e.g.
            # raised by a custom authentication backend for an unrelated
            # reason) is re-raised so genuine errors are not silently
            # masked. See GH #1006.
            if "\x00" not in username:
                raise
        if u is not None and u.is_active:
            request.user = u
            return True
        return False

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Avoid second query for RefreshToken since this method is invoked *after*
        # validate_refresh_token.
        rt = request.refresh_token_instance
        if not rt.access_token_id:
            try:
                return AccessToken.objects.get(source_refresh_token_id=rt.pk).scope
            except AccessToken.DoesNotExist:
                return []
        return rt.access_token.scope

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """
        Check refresh_token exists and refers to the right client.
        Also attach User instance to the request object
        """

        token_checksum = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
        rt = RefreshToken.objects.filter(token_checksum=token_checksum).select_related("access_token").first()

        if not rt:
            return False

        if rt.revoked is not None:
            grace_expired = rt.revoked <= timezone.now() - timedelta(
                seconds=oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS
            )
            # The grace window exists only to shield the *immediately preceding* refresh
            # token -- a client that retried because it did not receive the rotated
            # response. Rotation records that supersession in the same ``revoked`` column
            # as a deliberate revocation (the RFC 7009 /revoke/ endpoint, the admin,
            # RP-initiated logout, ``revoke_access_token``), so the two are told apart by
            # whether this token was ever consumed to mint a successor access token.
            #
            # A token that was repudiated rather than superseded was never consumed, and
            # must never be honored again: "the invalidation takes place immediately, and
            # the token cannot be used again after the revocation" (RFC 7009 section 2.1).
            # The same test also rejects a token replayed several generations down a
            # rotated chain, whose access token a later rotation has since revoked
            # (deleted) -- honoring that would defeat reuse protection (#1617).
            superseded = AccessToken.objects.filter(source_refresh_token=rt).exists()
            if grace_expired or not superseded:
                if oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION and rt.token_family:
                    # Set-based, not row by row: a family grows by one row per refresh
                    # and a client on a retry timer replays the stale token, so a per-row
                    # sweep cost a locking SELECT per token in the family, every time
                    # (#1809).
                    RefreshToken.revoke_family(rt.token_family)
                return False

        # Enforce REFRESH_TOKEN_EXPIRE_SECONDS at validation time. Historically the setting
        # only governed clear_expired() cleanup, so a refresh token past its configured
        # lifetime was still accepted until a sweep happened to remove it -- or forever, if
        # cleartokens never ran (#746). A live, actively-used refresh token is always paired
        # with an access token (rotation mints the pair together; non-rotating reuse keeps
        # it and bumps its ``expires``), so the expiry slides with the access token: the
        # token is dead REFRESH_TOKEN_EXPIRE_SECONDS after its access token expires. A
        # non-revoked token with no access token is an orphan from an out-of-band access
        # token deletion -- there is nothing left to refresh against, so reject it.
        if rt.revoked is None:
            if rt.access_token is None:
                return False
            # refresh_token_expire_timedelta() returns None when age expiry is disabled and
            # raises ImproperlyConfigured on a bad type, exactly as clear_expired does, so a
            # misconfiguration fails the same way here instead of raising an opaque TypeError.
            expire_delta = refresh_token_expire_timedelta()
            # ``<=`` so the deadline itself counts as expired, matching AccessToken.is_expired()
            # (``now >= expires``).
            if expire_delta and rt.access_token.expires + expire_delta <= timezone.now():
                return False

        request.user = rt.user
        # Use the raw token presented in the request, not rt.token: under hashed-at-rest
        # storage (COMPLIANT_BCP_RFC9700_TOKEN_STORAGE=True) the stored
        # column is blank, and oauthlib reuses request.refresh_token when rotation is off.
        request.refresh_token = refresh_token
        # Temporary store RefreshToken instance to be reused by get_original_scopes and save_bearer_token.
        request.refresh_token_instance = rt

        return rt.application == client

    def _save_id_token(self, jti, request, expires, *args, **kwargs):
        scopes = request.scope or " ".join(request.scopes)

        id_token = IDToken.objects.create(
            user=request.user,
            scope=scopes,
            expires=expires,
            jti=jti,
            application=request.client,
        )
        return id_token

    @classmethod
    def _get_additional_claims_is_request_agnostic(cls):
        return len(inspect.signature(cls.get_additional_claims).parameters) == 1

    def get_jwt_bearer_token(self, token, token_handler, request):
        # Despite the name, this is oauthlib's OpenID hook for issuing the OIDC
        # id_token as a bearer token — not the RFC 7523 jwt-bearer grant (which
        # is unimplemented) and unrelated to RFC 7523 client assertions (see
        # _authenticate_client_assertion).
        return self.get_id_token(token, token_handler, request)

    def get_claim_dict(self, request):
        if self._get_additional_claims_is_request_agnostic():
            claims = {"sub": lambda r: str(r.user.pk)}
        else:
            claims = {"sub": str(request.user.pk)}

        # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        if self._get_additional_claims_is_request_agnostic():
            add = self.get_additional_claims()
        else:
            add = self.get_additional_claims(request)
        claims.update(add)

        return claims

    def get_discovery_claims(self, request):
        claims = ["sub"]
        if self._get_additional_claims_is_request_agnostic():
            claims += list(self.get_claim_dict(request).keys())
        return claims

    def get_oidc_claims(self, token, token_handler, request):
        data = self.get_claim_dict(request)
        claims = {}

        # TODO if request.claims then return only the claims requested, but limited by granted scopes.

        for k, v in data.items():
            if not self.oidc_claim_scope or self.oidc_claim_scope.get(k) in request.scopes:
                claims[k] = v(request) if callable(v) else v
        return claims

    def get_id_token_dictionary(self, token, token_handler, request):
        """
        Get the claims to put in the ID Token.

        These claims are in addition to the claims automatically added by
        ``oauthlib`` - aud, iat, nonce, at_hash, c_hash.

        This function adds in iss, exp and auth_time, plus any claims added from
        calling ``get_oidc_claims()``
        """
        claims = self.get_oidc_claims(token, token_handler, request)

        expiration_time = timezone.now() + timedelta(seconds=oauth2_settings.ID_TOKEN_EXPIRE_SECONDS)

        auth_time = request.user.last_login
        if auth_time is None:
            auth_time = timezone.now()

        # RFC 7519 numeric dates are seconds since epoch in UTC.
        # For USE_TZ=False, naive datetimes represent local wall-clock time.
        # For USE_TZ=True, legacy naive values are interpreted as UTC.
        if timezone.is_naive(auth_time):
            if settings.USE_TZ:
                auth_time = auth_time.replace(tzinfo=datetime_timezone.utc)
            else:
                auth_time = make_aware(auth_time, timezone=timezone.get_default_timezone())

        auth_time = auth_time.astimezone(datetime_timezone.utc)

        # Required ID Token claims
        claims.update(
            **{
                "iss": self.get_oidc_issuer_endpoint(request),
                "exp": int(dateformat.format(expiration_time, "U")),
                "auth_time": int(auth_time.timestamp()),
                "jti": str(uuid.uuid4()),
            }
        )

        return claims, expiration_time

    def get_oidc_issuer_endpoint(self, request):
        return oauth2_settings.oidc_issuer(request)

    def finalize_id_token(self, id_token, token, token_handler, request):
        claims, expiration_time = self.get_id_token_dictionary(token, token_handler, request)
        id_token.update(**claims)
        # Workaround for oauthlib bug #746
        # https://github.com/oauthlib/oauthlib/issues/746
        if "nonce" not in id_token and request.nonce:
            id_token["nonce"] = request.nonce

        header = {
            "typ": "JWT",
            "alg": request.client.algorithm,
        }
        # RS256 consumers expect a kid in the header for verifying the token
        if request.client.algorithm == AbstractApplication.RS256_ALGORITHM:
            header["kid"] = request.client.jwk_key.thumbprint()

        jwt_token = jwt.JWT(
            header=json.dumps(header, default=str),
            claims=json.dumps(id_token, default=str),
        )
        jwt_token.make_signed_token(request.client.jwk_key)
        # Use the IDToken's database instead of making the assumption it is in 'default'.
        with transaction.atomic(using=router.db_for_write(IDToken)):
            id_token = self._save_id_token(id_token["jti"], request, expiration_time)
        # this is needed by django rest framework
        request.access_token = id_token
        request.id_token = id_token
        return jwt_token.serialize()

    def validate_jwt_bearer_token(self, token, scopes, request):
        return self.validate_id_token(token, scopes, request)

    def validate_id_token(self, token, scopes, request):
        """
        When users try to access resources, check that provided id_token is valid
        """
        if not token:
            return False

        id_token = self._load_id_token(token)
        if not id_token:
            return False

        if not id_token.allow_scopes(scopes):
            return False

        request.client = id_token.application
        request.user = id_token.user
        request.scopes = scopes
        # this is needed by django rest framework
        request.access_token = id_token
        return True

    def _load_id_token(self, token):
        key = self._get_key_for_token(token)
        if not key:
            return None
        try:
            jwt_token = jwt.JWT(key=key, jwt=token)
            claims = json.loads(jwt_token.claims)
            return IDToken.objects.get(jti=claims["jti"])
        except (JWException, JWTExpired, IDToken.DoesNotExist):
            return None

    def _get_key_for_token(self, token):
        """
        Peek at the unvalidated token to discover who it was issued for
        and then use that to load that application and its key.
        """
        unverified_token = jws.JWS()
        unverified_token.deserialize(token)
        claims = json.loads(unverified_token.objects["payload"].decode("utf-8"))
        if "aud" not in claims:
            return None
        application = self._get_client_by_audience(claims["aud"])
        if application:
            return application.jwk_key

    def _get_client_by_audience(self, audience):
        """
        Load a client by the aud claim in a JWT.
        aud may be multi-valued, if your provider makes it so.
        This function is separate to allow further customization.
        """
        if isinstance(audience, str):
            audience = [audience]
        return Application.objects.filter(client_id__in=audience).first()

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        # TODO: Fix to validate when necessary according
        # https://github.com/idan/oauthlib/blob/master/oauthlib/oauth2/rfc6749/request_validator.py#L556
        # http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest id_token_hint section
        return True

    def get_authorization_code_nonce(self, client_id, code, redirect_uri, request):
        """Extracts nonce from saved authorization code.
        If present in the Authentication Request, Authorization
        Servers MUST include a nonce Claim in the ID Token with the
        Claim Value being the nonce value sent in the Authentication
        Request. Authorization Servers SHOULD perform no other
        processing on nonce values used. The nonce value is a
        case-sensitive string.
        Only code param should be sufficient to retrieve grant code from
        any storage you are using. However, `client_id` and `redirect_uri`
        have been validated and can be used also.
        :param client_id: Unicode client identifier
        :param code: Unicode authorization code grant
        :param redirect_uri: Unicode absolute URI
        :return: Unicode nonce
        Method is used by:
            - Authorization Token Grant Dispatcher
        """
        nonce = Grant.objects.filter(code=code).values_list("nonce", flat=True).first()
        if nonce:
            return nonce

    def get_userinfo_claims(self, request):
        """
        Generates and saves a new JWT for this request, and returns it as the
        current user's claims.

        """
        return self.get_oidc_claims(request.access_token, None, request)

    def get_additional_claims(self, request):
        return {}

    def is_origin_allowed(self, client_id, origin, request, *args, **kwargs):
        """Indicate if the given origin is allowed to access the token endpoint
        via Cross-Origin Resource Sharing (CORS).  CORS is used by browser-based
        clients, such as Single-Page Applications, to perform the Authorization
        Code Grant.

        Verifies if request's origin is within Application's allowed origins list.
        """
        return request.client.origin_allowed(origin)
