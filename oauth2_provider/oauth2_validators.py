import base64
import binascii
import hashlib
import http.client
import inspect
import json
import logging
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta
from urllib.parse import unquote_plus

import requests
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.hashers import check_password, identify_hasher
from django.core.exceptions import ObjectDoesNotExist
from django.db import router, transaction
from django.http import HttpRequest
from django.utils import dateformat, timezone
from django.utils.crypto import constant_time_compare
from django.utils.timezone import make_aware
from django.utils.translation import gettext_lazy as _
from jwcrypto import jws, jwt
from jwcrypto.common import JWException
from jwcrypto.jwt import JWTExpired
from oauthlib.oauth2.rfc6749 import errors, utils
from oauthlib.openid import RequestValidator

from .exceptions import FatalClientError
from .models import (
    AbstractApplication,
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
)
from .scopes import get_scopes_backend
from .settings import oauth2_settings
from .utils import get_timezone


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


class OAuth2Validator(RequestValidator):
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
            log.debug("Failed basic auth: %r can't be decoded as base64", auth_string)
            return False

        try:
            auth_string_decoded = b64_decoded.decode(encoding)
        except UnicodeDecodeError:
            log.debug("Failed basic auth: %r can't be decoded as unicode by %r", auth_string, encoding)
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
        elif (
            request.client.client_type == "public"
            and request.grant_type == "urn:ietf:params:oauth:grant-type:device_code"
        ):
            return True
        elif not self._check_secret(client_secret, request.client.client_secret):
            log.debug("Failed basic auth: wrong client secret %s" % client_secret)
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
        elif (
            request.client.client_type == "public"
            and request.grant_type == "urn:ietf:params:oauth:grant-type:device_code"
        ):
            return True
        elif not self._check_secret(client_secret, request.client.client_secret):
            log.debug("Failed body auth: wrong client secret %s" % client_secret)
            return False
        else:
            return True

    def _load_application(self, client_id, request):
        """
        If request.client was not set, load application instance for given
        client_id and store it in request.client
        """
        if request.client:
            # check for cached client, to save the db hit if this has already been loaded
            if not isinstance(request.client, Application):
                # resetting request.client (client_id=%r): not an Application, something else set request.client erroneously
                request.client = None
            elif request.client.client_id != client_id:
                # resetting request.client (client_id=%r): request.client.client_id does not match the given client_id
                request.client = None
            elif not request.client.is_usable(request):
                # resetting request.client (client_id=%r): request.client is a valid Application, but is not usable
                request.client = None
            else:
                # request.client is a valid Application, reusing it
                return request.client
        try:
            # cache not hit, loading application from database for client_id %r
            client = Application.objects.get(client_id=client_id)
            if not client.is_usable(request):
                # Failed to load application: Application %r is not usable
                return None
            request.client = client
            # Loaded application with client_id %r from database
            return request.client
        except Application.DoesNotExist:
            # Failed to load application: Application with client_id %r does not exist
            return None

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
        See rfc:`2.3.1` for more details
        """
        authenticated = self._authenticate_basic_auth(request)

        if not authenticated:
            authenticated = self._authenticate_request_body(request)

        return authenticated

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

    def _get_token_from_authentication_server(
        self, token, introspection_url, introspection_token, introspection_credentials
    ):
        """Use external introspection endpoint to "crack open" the token.
        :param introspection_url: introspection endpoint URL
        :param introspection_token: Bearer token
        :param introspection_credentials: Basic Auth credentials (id,secret)
        :return: :class:`models.AccessToken`

        Some RFC 7662 implementations (including this one) use a Bearer token while others use Basic
        Auth. Depending on the external AS's implementation, provide either the introspection_token
        or the introspection_credentials.

        If the resulting access_token identifies a username (e.g. Authorization Code grant), add
        that user to the UserModel. Also cache the access_token up until its expiry time or a
        configured maximum time.

        """
        headers = None
        if introspection_token:
            headers = {"Authorization": "Bearer {}".format(introspection_token)}
        elif introspection_credentials:
            client_id = introspection_credentials[0].encode("utf-8")
            client_secret = introspection_credentials[1].encode("utf-8")
            basic_auth = base64.b64encode(client_id + b":" + client_secret)
            headers = {"Authorization": "Basic {}".format(basic_auth.decode("utf-8"))}

        try:
            response = requests.post(introspection_url, data={"token": token}, headers=headers)
        except requests.exceptions.RequestException:
            log.exception("Introspection: Failed POST to %r in token lookup", introspection_url)
            return None

        # Log an exception when response from auth server is not successful
        if response.status_code != http.client.OK:
            log.exception(
                "Introspection: Failed to get a valid response "
                "from authentication server. Status code: {}, "
                "Reason: {}.".format(response.status_code, response.reason)
            )
            return None

        try:
            content = response.json()
        except ValueError:
            log.exception("Introspection: Failed to parse response as json")
            return None

        if "active" in content and content["active"] is True:
            if "username" in content:
                user = self.get_or_create_user_from_content(content)
            else:
                user = None

            max_caching_time = datetime.now() + timedelta(
                seconds=oauth2_settings.RESOURCE_SERVER_TOKEN_CACHING_SECONDS
            )

            if "exp" in content:
                expires = datetime.utcfromtimestamp(content["exp"])
                if expires > max_caching_time:
                    expires = max_caching_time
            else:
                expires = max_caching_time

            scope = content.get("scope", "")

            if settings.USE_TZ:
                expires = make_aware(
                    expires, timezone=get_timezone(oauth2_settings.AUTHENTICATION_SERVER_EXP_TIME_ZONE)
                )

            token_checksum = hashlib.sha256(token.encode("utf-8")).hexdigest()
            access_token, _created = AccessToken.objects.update_or_create(
                token_checksum=token_checksum,
                defaults={
                    "token": token,
                    "user": user,
                    "application": None,
                    "scope": scope,
                    "expires": expires,
                },
            )

            return access_token

    def validate_bearer_token(self, token, scopes, request):
        """
        When users try to access resources, check that provided token is valid
        """
        if not token:
            return False

        introspection_url = oauth2_settings.RESOURCE_SERVER_INTROSPECTION_URL
        introspection_token = oauth2_settings.RESOURCE_SERVER_AUTH_TOKEN
        introspection_credentials = oauth2_settings.RESOURCE_SERVER_INTROSPECTION_CREDENTIALS

        access_token = self._load_access_token(token)

        # if there is no token or it's invalid then introspect the token if there's an external OAuth server
        if not access_token or not access_token.is_valid(scopes):
            if introspection_url and (introspection_token or introspection_credentials):
                access_token = self._get_token_from_authentication_server(
                    token, introspection_url, introspection_token, introspection_credentials
                )

        if access_token and access_token.is_valid(scopes):
            request.client = access_token.application
            request.user = access_token.user
            request.scopes = list(access_token.scopes)

            # this is needed by django rest framework
            request.access_token = access_token
            return True
        else:
            self._set_oauth2_error_on_request(request, access_token, scopes)
            return False

    def _load_access_token(self, token):
        token_checksum = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return (
            AccessToken.objects.select_related("application", "user")
            .filter(token_checksum=token_checksum)
            .first()
        )

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
        return request.client.allows_grant_type(*GRANT_TYPE_MAPPING[grant_type])

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """
        We currently do not support the Authorization Endpoint Response Types registry as in
        rfc:`8.4`, so validate the response_type only if it matches "code" or "token"
        """
        if response_type == "code":
            return client.allows_grant_type(AbstractApplication.GRANT_AUTHORIZATION_CODE)
        elif response_type == "token":
            return client.allows_grant_type(AbstractApplication.GRANT_IMPLICIT)
        elif response_type == "id_token":
            return client.allows_grant_type(AbstractApplication.GRANT_IMPLICIT)
        elif response_type == "id_token token":
            return client.allows_grant_type(AbstractApplication.GRANT_IMPLICIT)
        elif response_type == "code id_token":
            return client.allows_grant_type(AbstractApplication.GRANT_OPENID_HYBRID)
        elif response_type == "code token":
            return client.allows_grant_type(AbstractApplication.GRANT_OPENID_HYBRID)
        elif response_type == "code id_token token":
            return client.allows_grant_type(AbstractApplication.GRANT_OPENID_HYBRID)
        else:
            return False

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

    def _save_bearer_token(self, token, request, *args, **kwargs):
        """
        Save access and refresh token.

        If refresh token is issued, remove or reuse old refresh token as in rfc:`6`.

        @see: https://rfc-editor.org/rfc/rfc6749.html#section-6
        """

        if "scope" not in token:
            raise FatalClientError("Failed to renew access token: missing scope")

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
                access_token.token = token["access_token"]
                access_token.application = request.client
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

                    previous_access_token = AccessToken.objects.filter(
                        source_refresh_token=refresh_token_instance
                    ).first()
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
                    token["access_token"] = previous_access_token.token
                    token["refresh_token"] = (
                        RefreshToken.objects.filter(access_token=previous_access_token).first().token
                    )
                    token["scope"] = previous_access_token.scope

        # No refresh token should be created, just access token
        else:
            self._create_access_token(expires, request, token)

    def _create_access_token(self, expires, request, token, source_refresh_token=None):
        id_token = token.get("id_token", None)
        if id_token:
            id_token = self._load_id_token(id_token)
        return AccessToken.objects.create(
            user=request.user,
            scope=token["scope"],
            expires=expires,
            token=token["access_token"],
            id_token=id_token,
            application=request.client,
            source_refresh_token=source_refresh_token,
        )

    def _create_authorization_code(self, request, code, expires=None):
        if not expires:
            expires = timezone.now() + timedelta(seconds=oauth2_settings.AUTHORIZATION_CODE_EXPIRE_SECONDS)
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
        )

    def _create_refresh_token(self, request, refresh_token_code, access_token, previous_refresh_token):
        if previous_refresh_token:
            token_family = previous_refresh_token.token_family
        else:
            token_family = uuid.uuid4()
        return RefreshToken.objects.create(
            user=request.user,
            token=refresh_token_code,
            application=request.client,
            access_token=access_token,
            token_family=token_family,
        )

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

        token_type = token_types.get(token_type_hint, AccessToken)
        try:
            token_type.objects.get(token=token).revoke()
        except ObjectDoesNotExist:
            for other_type in [_t for _t in token_types.values() if _t != token_type]:
                # slightly inefficient on Python2, but the queryset contains only one instance
                list(map(lambda t: t.revoke(), other_type.objects.filter(token=token)))

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        Check username and password correspond to a valid and active User
        """
        # Passing the optional HttpRequest adds compatibility for backends
        # which depend on its presence. Create one with attributes likely
        # to be used.
        http_request = HttpRequest()
        http_request.path = request.uri
        http_request.method = request.http_method
        getattr(http_request, request.http_method).update(dict(request.decoded_body))
        http_request.META = request.headers
        u = authenticate(http_request, username=username, password=password)
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

        rt = RefreshToken.objects.filter(token=refresh_token).select_related("access_token").first()

        if not rt:
            return False

        if rt.revoked is not None and rt.revoked <= timezone.now() - timedelta(
            seconds=oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS
        ):
            if oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION and rt.token_family:
                rt_token_family = RefreshToken.objects.filter(token_family=rt.token_family)
                for related_rt in rt_token_family.all():
                    related_rt.revoke()
            return False

        request.user = rt.user
        request.refresh_token = rt.token
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
        # Required ID Token claims
        claims.update(
            **{
                "iss": self.get_oidc_issuer_endpoint(request),
                "exp": int(dateformat.format(expiration_time, "U")),
                "auth_time": int(dateformat.format(request.user.last_login, "U")),
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
