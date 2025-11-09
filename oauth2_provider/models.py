import hashlib
import logging
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Callable, Optional, Union
from urllib.parse import parse_qsl, urlparse

from django.apps import apps
from django.conf import settings
from django.contrib.auth.hashers import identify_hasher, make_password
from django.core.exceptions import ImproperlyConfigured
from django.db import models, router, transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from jwcrypto import jwk
from jwcrypto.common import base64url_encode
from oauthlib.oauth2.rfc6749 import errors

from .generators import generate_client_id, generate_client_secret
from .scopes import get_scopes_backend
from .settings import oauth2_settings
from .utils import jwk_from_pem
from .validators import AllowedURIValidator


logger = logging.getLogger(__name__)


class ClientSecretField(models.CharField):
    def pre_save(self, model_instance, add):
        secret = getattr(model_instance, self.attname)
        should_be_hashed = getattr(model_instance, "hash_client_secret", True)
        if not should_be_hashed:
            return super().pre_save(model_instance, add)

        try:
            hasher = identify_hasher(secret)
            logger.debug(f"{model_instance}: {self.attname} is already hashed with {hasher}.")
        except ValueError:
            logger.debug(f"{model_instance}: {self.attname} is not hashed; hashing it now.")
            hashed_secret = make_password(secret, hasher=oauth2_settings.CLIENT_SECRET_HASHER)
            setattr(model_instance, self.attname, hashed_secret)
            return hashed_secret
        return super().pre_save(model_instance, add)


class TokenChecksumField(models.CharField):
    def pre_save(self, model_instance, add):
        token = getattr(model_instance, "token")
        checksum = hashlib.sha256(token.encode("utf-8")).hexdigest()
        setattr(model_instance, self.attname, checksum)
        return super().pre_save(model_instance, add)


class AbstractApplication(models.Model):
    """
    An Application instance represents a Client on the Authorization server.
    Usually an Application is created manually by client's developers after
    logging in on an Authorization Server.

    Fields:

    * :attr:`client_id` The client identifier issued to the client during the
                        registration process as described in :rfc:`2.2`
    * :attr:`user` ref to a Django user
    * :attr:`redirect_uris` The list of allowed redirect uri. The string
                            consists of valid URLs separated by space
    * :attr:`post_logout_redirect_uris` The list of allowed redirect uris after
                                        an RP initiated logout. The string
                                        consists of valid URLs separated by space
    * :attr:`client_type` Client type as described in :rfc:`2.1`
    * :attr:`authorization_grant_type` Authorization flows available to the
                                       Application
    * :attr:`client_secret` Confidential secret issued to the client during
                            the registration process as described in :rfc:`2.2`
    * :attr:`name` Friendly name for the Application
    """

    CLIENT_CONFIDENTIAL = "confidential"
    CLIENT_PUBLIC = "public"
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _("Confidential")),
        (CLIENT_PUBLIC, _("Public")),
    )

    GRANT_AUTHORIZATION_CODE = "authorization-code"
    GRANT_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    GRANT_IMPLICIT = "implicit"
    GRANT_PASSWORD = "password"
    GRANT_CLIENT_CREDENTIALS = "client-credentials"
    GRANT_OPENID_HYBRID = "openid-hybrid"
    GRANT_TYPES = (
        (GRANT_AUTHORIZATION_CODE, _("Authorization code")),
        (GRANT_DEVICE_CODE, _("Device Code")),
        (GRANT_IMPLICIT, _("Implicit")),
        (GRANT_PASSWORD, _("Resource owner password-based")),
        (GRANT_CLIENT_CREDENTIALS, _("Client credentials")),
        (GRANT_OPENID_HYBRID, _("OpenID connect hybrid")),
    )

    NO_ALGORITHM = ""
    RS256_ALGORITHM = "RS256"
    HS256_ALGORITHM = "HS256"
    ALGORITHM_TYPES = (
        (NO_ALGORITHM, _("No OIDC support")),
        (RS256_ALGORITHM, _("RSA with SHA-2 256")),
        (HS256_ALGORITHM, _("HMAC with SHA-2 256")),
    )

    id = models.BigAutoField(primary_key=True)
    client_id = models.CharField(max_length=100, unique=True, default=generate_client_id, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="%(app_label)s_%(class)s",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    redirect_uris = models.TextField(
        blank=True,
        help_text=_("Allowed URIs list, space separated"),
    )
    post_logout_redirect_uris = models.TextField(
        blank=True,
        help_text=_("Allowed Post Logout URIs list, space separated"),
        default="",
    )
    client_type = models.CharField(max_length=32, choices=CLIENT_TYPES)
    authorization_grant_type = models.CharField(max_length=44, choices=GRANT_TYPES)
    client_secret = ClientSecretField(
        max_length=255,
        blank=True,
        default=generate_client_secret,
        db_index=True,
        help_text=_("Hashed on Save. Copy it now if this is a new secret."),
    )
    hash_client_secret = models.BooleanField(default=True)
    name = models.CharField(max_length=255, blank=True)
    skip_authorization = models.BooleanField(default=False)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    algorithm = models.CharField(max_length=5, choices=ALGORITHM_TYPES, default=NO_ALGORITHM, blank=True)
    allowed_origins = models.TextField(
        blank=True,
        help_text=_("Allowed origins list to enable CORS, space separated"),
        default="",
    )

    class Meta:
        abstract = True

    def __str__(self):
        return self.name or self.client_id

    @property
    def default_redirect_uri(self):
        """
        Returns the default redirect_uri, *if* only one is registered.
        """
        if self.redirect_uris:
            uris = self.redirect_uris.split()
            if len(uris) == 1:
                return self.redirect_uris.split().pop(0)
            raise errors.MissingRedirectURIError()

        assert False, (
            "If you are using implicit, authorization_code "
            "or all-in-one grant_type, you must define "
            "redirect_uris field in your Application model"
        )

    def redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """
        return redirect_to_uri_allowed(uri, self.redirect_uris.split())

    def post_logout_redirect_uri_allowed(self, uri):
        """
        Checks if given URI is one of the items in :attr:`post_logout_redirect_uris` string

        :param uri: URI to check
        """
        return redirect_to_uri_allowed(uri, self.post_logout_redirect_uris.split())

    def origin_allowed(self, origin):
        """
        Checks if given origin is one of the items in :attr:`allowed_origins` string

        :param origin: Origin to check
        """
        return self.allowed_origins and is_origin_allowed(origin, self.allowed_origins.split())

    def clean(self):
        from django.core.exceptions import ValidationError

        grant_types = (
            AbstractApplication.GRANT_AUTHORIZATION_CODE,
            AbstractApplication.GRANT_IMPLICIT,
            AbstractApplication.GRANT_OPENID_HYBRID,
        )
        hs_forbidden_grant_types = (
            AbstractApplication.GRANT_IMPLICIT,
            AbstractApplication.GRANT_OPENID_HYBRID,
        )

        redirect_uris = self.redirect_uris.strip().split()
        allowed_schemes = set(s.lower() for s in self.get_allowed_schemes())

        if redirect_uris:
            validator = AllowedURIValidator(
                allowed_schemes,
                name="redirect uri",
                allow_path=True,
                allow_query=True,
                allow_hostname_wildcard=oauth2_settings.ALLOW_URI_WILDCARDS,
            )
            for uri in redirect_uris:
                validator(uri)

        elif self.authorization_grant_type in grant_types:
            raise ValidationError(
                _("redirect_uris cannot be empty with grant_type {grant_type}").format(
                    grant_type=self.authorization_grant_type
                )
            )
        allowed_origins = self.allowed_origins.strip().split()
        if allowed_origins:
            # oauthlib allows only https scheme for CORS
            validator = AllowedURIValidator(
                oauth2_settings.ALLOWED_SCHEMES,
                "allowed origin",
                allow_hostname_wildcard=oauth2_settings.ALLOW_URI_WILDCARDS,
            )
            for uri in allowed_origins:
                validator(uri)

        if self.algorithm == AbstractApplication.RS256_ALGORITHM:
            if not oauth2_settings.OIDC_RSA_PRIVATE_KEY:
                raise ValidationError(_("You must set OIDC_RSA_PRIVATE_KEY to use RSA algorithm"))

        if self.algorithm == AbstractApplication.HS256_ALGORITHM:
            if any(
                (
                    self.authorization_grant_type in hs_forbidden_grant_types,
                    self.client_type == Application.CLIENT_PUBLIC,
                )
            ):
                raise ValidationError(_("You cannot use HS256 with public grants or clients"))

    def get_absolute_url(self):
        return reverse("oauth2_provider:detail", args=[str(self.pk)])

    def get_allowed_schemes(self):
        """
        Returns the list of redirect schemes allowed by the Application.
        By default, returns `ALLOWED_REDIRECT_URI_SCHEMES`.
        """
        return oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES

    def allows_grant_type(self, *grant_types):
        return self.authorization_grant_type in grant_types

    def is_usable(self, request):
        """
        Determines whether the application can be used.

        :param request: The oauthlib.common.Request being processed.
        """
        return True

    @property
    def jwk_key(self):
        if self.algorithm == AbstractApplication.RS256_ALGORITHM:
            if not oauth2_settings.OIDC_RSA_PRIVATE_KEY:
                raise ImproperlyConfigured("You must set OIDC_RSA_PRIVATE_KEY to use RSA algorithm")
            return jwk_from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY)
        elif self.algorithm == AbstractApplication.HS256_ALGORITHM:
            return jwk.JWK(kty="oct", k=base64url_encode(self.client_secret))
        raise ImproperlyConfigured("This application does not support signed tokens")


class ApplicationManager(models.Manager):
    def get_by_natural_key(self, client_id):
        return self.get(client_id=client_id)


class Application(AbstractApplication):
    objects = ApplicationManager()

    class Meta(AbstractApplication.Meta):
        swappable = "OAUTH2_PROVIDER_APPLICATION_MODEL"

    def natural_key(self):
        return (self.client_id,)


class AbstractGrant(models.Model):
    """
    A Grant instance represents a token with a short lifetime that can
    be swapped for an access token, as described in :rfc:`4.1.2`

    Fields:

    * :attr:`user` The Django user who requested the grant
    * :attr:`code` The authorization code generated by the authorization server
    * :attr:`application` Application instance this grant was asked for
    * :attr:`expires` Expire time in seconds, defaults to
                      :data:`settings.AUTHORIZATION_CODE_EXPIRE_SECONDS`
    * :attr:`redirect_uri` Self explained
    * :attr:`scope` Required scopes, optional
    * :attr:`code_challenge` PKCE code challenge
    * :attr:`code_challenge_method` PKCE code challenge transform algorithm
    """

    CODE_CHALLENGE_PLAIN = "plain"
    CODE_CHALLENGE_S256 = "S256"
    CODE_CHALLENGE_METHODS = ((CODE_CHALLENGE_PLAIN, "plain"), (CODE_CHALLENGE_S256, "S256"))

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="%(app_label)s_%(class)s"
    )
    code = models.CharField(max_length=255, unique=True)  # code comes from oauthlib
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE)
    expires = models.DateTimeField()
    redirect_uri = models.TextField()
    scope = models.TextField(blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    code_challenge = models.CharField(max_length=128, blank=True, default="")
    code_challenge_method = models.CharField(
        max_length=10, blank=True, default="", choices=CODE_CHALLENGE_METHODS
    )

    nonce = models.CharField(max_length=255, blank=True, default="")
    claims = models.TextField(blank=True)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def redirect_uri_allowed(self, uri):
        return uri == self.redirect_uri

    def __str__(self):
        return self.code

    class Meta:
        abstract = True


class Grant(AbstractGrant):
    class Meta(AbstractGrant.Meta):
        swappable = "OAUTH2_PROVIDER_GRANT_MODEL"


class AbstractAccessToken(models.Model):
    """
    An AccessToken instance represents the actual access token to
    access user's resources, as in :rfc:`5`.

    Fields:

    * :attr:`user` The Django user representing resources" owner
    * :attr:`source_refresh_token` If from a refresh, the consumed RefeshToken
    * :attr:`token` Access token
    * :attr:`application` Application instance
    * :attr:`expires` Date and time of token expiration, in DateTime format
    * :attr:`scope` Allowed scopes
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
    )
    source_refresh_token = models.OneToOneField(
        # unique=True implied by the OneToOneField
        oauth2_settings.REFRESH_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refreshed_access_token",
    )
    token = models.TextField()
    token_checksum = TokenChecksumField(
        max_length=64,
        blank=False,
        unique=True,
        db_index=True,
    )
    id_token = models.OneToOneField(
        oauth2_settings.ID_TOKEN_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="access_token",
    )
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )
    expires = models.DateTimeField()
    scope = models.TextField(blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def revoke(self):
        """
        Convenience method to uniform tokens" interface, for now
        simply remove this token from the database in order to revoke it.
        """
        self.delete()

    @property
    def scopes(self):
        """
        Returns a dictionary of allowed scope names (as keys) with their descriptions (as values)
        """
        all_scopes = get_scopes_backend().get_all_scopes()
        token_scopes = self.scope.split()
        return {name: desc for name, desc in all_scopes.items() if name in token_scopes}

    def __str__(self):
        return self.token

    class Meta:
        abstract = True


class AccessToken(AbstractAccessToken):
    class Meta(AbstractAccessToken.Meta):
        swappable = "OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL"


class AbstractRefreshToken(models.Model):
    """
    A RefreshToken instance represents a token that can be swapped for a new
    access token when it expires.

    Fields:

    * :attr:`user` The Django user representing resources" owner
    * :attr:`token` Token value
    * :attr:`application` Application instance
    * :attr:`access_token` AccessToken instance this refresh token is
                           bounded to
    * :attr:`revoked` Timestamp of when this refresh token was revoked
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="%(app_label)s_%(class)s"
    )
    token = models.CharField(max_length=255)
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE)
    access_token = models.OneToOneField(
        oauth2_settings.ACCESS_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refresh_token",
    )
    token_family = models.UUIDField(null=True, blank=True, editable=False)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    revoked = models.DateTimeField(null=True)

    def revoke(self):
        """
        Mark this refresh token revoked and revoke related access token
        """
        access_token_model = get_access_token_model()
        access_token_database = router.db_for_write(access_token_model)
        refresh_token_model = get_refresh_token_model()

        # Use the access_token_database instead of making the assumption it is in 'default'.
        with transaction.atomic(using=access_token_database):
            token = refresh_token_model.objects.select_for_update().filter(pk=self.pk, revoked__isnull=True)
            if not token:
                return
            self = list(token)[0]

            with suppress(access_token_model.DoesNotExist):
                access_token_model.objects.get(id=self.access_token_id).revoke()

            self.access_token = None
            self.revoked = timezone.now()
            self.save()

    def __str__(self):
        return self.token

    class Meta:
        abstract = True
        unique_together = (
            "token",
            "revoked",
        )


class RefreshToken(AbstractRefreshToken):
    class Meta(AbstractRefreshToken.Meta):
        swappable = "OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL"


class AbstractIDToken(models.Model):
    """
    An IDToken instance represents the actual token to
    access user's resources, as in :openid:`2`.

    Fields:

    * :attr:`user` The Django user representing resources' owner
    * :attr:`jti` ID token JWT Token ID, to identify an individual token
    * :attr:`application` Application instance
    * :attr:`expires` Date and time of token expiration, in DateTime format
    * :attr:`scope` Allowed scopes
    * :attr:`created` Date and time of token creation, in DateTime format
    * :attr:`updated` Date and time of token update, in DateTime format
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
    )
    jti = models.UUIDField(unique=True, default=uuid.uuid4, editable=False, verbose_name="JWT Token ID")
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
    )
    expires = models.DateTimeField()
    scope = models.TextField(blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def revoke(self):
        """
        Convenience method to uniform tokens' interface, for now
        simply remove this token from the database in order to revoke it.
        """
        self.delete()

    @property
    def scopes(self):
        """
        Returns a dictionary of allowed scope names (as keys) with their descriptions (as values)
        """
        all_scopes = get_scopes_backend().get_all_scopes()
        token_scopes = self.scope.split()
        return {name: desc for name, desc in all_scopes.items() if name in token_scopes}

    def __str__(self):
        return "JTI: {self.jti} User: {self.user_id}".format(self=self)

    class Meta:
        abstract = True


class IDToken(AbstractIDToken):
    class Meta(AbstractIDToken.Meta):
        swappable = "OAUTH2_PROVIDER_ID_TOKEN_MODEL"


class AbstractDeviceGrant(models.Model):
    class Meta:
        abstract = True
        constraints = [
            models.UniqueConstraint(
                fields=["device_code"],
                name="%(app_label)s_%(class)s_unique_device_code",
            ),
        ]

    AUTHORIZED = "authorized"
    AUTHORIZATION_PENDING = "authorization-pending"
    EXPIRED = "expired"
    DENIED = "denied"

    DEVICE_FLOW_STATUS = (
        (AUTHORIZED, _("Authorized")),
        (AUTHORIZATION_PENDING, _("Authorization pending")),
        (EXPIRED, _("Expired")),
        (DENIED, _("Denied")),
    )

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="%(app_label)s_%(class)s",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )
    device_code = models.CharField(max_length=100, unique=True)
    user_code = models.CharField(max_length=100)
    scope = models.CharField(max_length=64, null=True)
    interval = models.IntegerField(default=5)
    expires = models.DateTimeField()
    status = models.CharField(
        max_length=64, blank=True, choices=DEVICE_FLOW_STATUS, default=AUTHORIZATION_PENDING
    )
    client_id = models.CharField(max_length=100, db_index=True)
    last_checked = models.DateTimeField(auto_now=True)

    def is_expired(self):
        """
        Check device flow session expiration and set the status to "expired" if current time
        is past the "expires" deadline.
        """
        if self.status == self.EXPIRED:
            return True

        now = datetime.now(tz=dt_timezone.utc)
        if now >= self.expires:
            self.status = self.EXPIRED
            self.save(update_fields=["status"])
            return True

        return False


class DeviceGrant(AbstractDeviceGrant):
    class Meta(AbstractDeviceGrant.Meta):
        swappable = "OAUTH2_PROVIDER_DEVICE_GRANT_MODEL"


@dataclass
class DeviceRequest:
    # https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
    # scope is optional
    client_id: str
    scope: Optional[str] = None


@dataclass
class DeviceCodeResponse:
    verification_uri: str
    expires_in: int
    user_code: int
    device_code: str
    interval: int
    verification_uri_complete: Optional[Union[str, Callable]] = None


def create_device_grant(device_request: DeviceRequest, device_response: DeviceCodeResponse) -> DeviceGrant:
    now = datetime.now(tz=dt_timezone.utc)

    return DeviceGrant.objects.create(
        client_id=device_request.client_id,
        device_code=device_response.device_code,
        user_code=device_response.user_code,
        scope=device_request.scope,
        expires=now + timedelta(seconds=device_response.expires_in),
    )


def get_application_model():
    """Return the Application model that is active in this project."""
    return apps.get_model(oauth2_settings.APPLICATION_MODEL)


def get_device_grant_model():
    """Return the DeviceGrant model that is active in this project."""
    return apps.get_model(oauth2_settings.DEVICE_GRANT_MODEL)


def get_grant_model():
    """Return the Grant model that is active in this project."""
    return apps.get_model(oauth2_settings.GRANT_MODEL)


def get_access_token_model():
    """Return the AccessToken model that is active in this project."""
    return apps.get_model(oauth2_settings.ACCESS_TOKEN_MODEL)


def get_id_token_model():
    """Return the IDToken model that is active in this project."""
    return apps.get_model(oauth2_settings.ID_TOKEN_MODEL)


def get_refresh_token_model():
    """Return the RefreshToken model that is active in this project."""
    return apps.get_model(oauth2_settings.REFRESH_TOKEN_MODEL)


def get_application_admin_class():
    """Return the Application admin class that is active in this project."""
    application_admin_class = oauth2_settings.APPLICATION_ADMIN_CLASS
    return application_admin_class


def get_access_token_admin_class():
    """Return the AccessToken admin class that is active in this project."""
    access_token_admin_class = oauth2_settings.ACCESS_TOKEN_ADMIN_CLASS
    return access_token_admin_class


def get_grant_admin_class():
    """Return the Grant admin class that is active in this project."""
    grant_admin_class = oauth2_settings.GRANT_ADMIN_CLASS
    return grant_admin_class


def get_id_token_admin_class():
    """Return the IDToken admin class that is active in this project."""
    id_token_admin_class = oauth2_settings.ID_TOKEN_ADMIN_CLASS
    return id_token_admin_class


def get_refresh_token_admin_class():
    """Return the RefreshToken admin class that is active in this project."""
    refresh_token_admin_class = oauth2_settings.REFRESH_TOKEN_ADMIN_CLASS
    return refresh_token_admin_class


def clear_expired():
    def batch_delete(queryset, query):
        CLEAR_EXPIRED_TOKENS_BATCH_SIZE = oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_SIZE
        CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL = oauth2_settings.CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL
        current_no = start_no = queryset.count()

        while current_no:
            flat_queryset = queryset.values_list("id", flat=True)[:CLEAR_EXPIRED_TOKENS_BATCH_SIZE]
            batch_length = flat_queryset.count()
            queryset.model.objects.filter(id__in=list(flat_queryset)).delete()
            logger.debug(f"{batch_length} tokens deleted, {current_no - batch_length} left")
            queryset = queryset.model.objects.filter(query)
            time.sleep(CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL)
            current_no = queryset.count()

        stop_no = queryset.model.objects.filter(query).count()
        deleted = start_no - stop_no
        return deleted

    now = timezone.now()
    refresh_expire_at = None
    access_token_model = get_access_token_model()
    refresh_token_model = get_refresh_token_model()
    id_token_model = get_id_token_model()
    grant_model = get_grant_model()
    REFRESH_TOKEN_EXPIRE_SECONDS = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS

    if REFRESH_TOKEN_EXPIRE_SECONDS:
        if not isinstance(REFRESH_TOKEN_EXPIRE_SECONDS, timedelta):
            try:
                REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
            except TypeError:
                e = "REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds"
                raise ImproperlyConfigured(e)
        refresh_expire_at = now - REFRESH_TOKEN_EXPIRE_SECONDS

    if refresh_expire_at:
        revoked_query = models.Q(revoked__lt=refresh_expire_at)
        revoked = refresh_token_model.objects.filter(revoked_query)

        revoked_deleted_no = batch_delete(revoked, revoked_query)
        logger.info("%s Revoked refresh tokens deleted", revoked_deleted_no)

        expired_query = models.Q(access_token__expires__lt=refresh_expire_at)
        expired = refresh_token_model.objects.filter(expired_query)

        expired_deleted_no = batch_delete(expired, expired_query)
        logger.info("%s Expired refresh tokens deleted", expired_deleted_no)
    else:
        logger.info("refresh_expire_at is %s. No refresh tokens deleted.", refresh_expire_at)

    access_token_query = models.Q(refresh_token__isnull=True, expires__lt=now)
    access_tokens = access_token_model.objects.filter(access_token_query)

    access_tokens_delete_no = batch_delete(access_tokens, access_token_query)
    logger.info("%s Expired access tokens deleted", access_tokens_delete_no)

    id_token_query = models.Q(access_token__isnull=True, expires__lt=now)
    id_tokens = id_token_model.objects.filter(id_token_query)

    id_tokens_delete_no = batch_delete(id_tokens, id_token_query)
    logger.info("%s Expired ID tokens deleted", id_tokens_delete_no)

    grants_query = models.Q(expires__lt=now)
    grants = grant_model.objects.filter(grants_query)

    grants_deleted_no = batch_delete(grants, grants_query)
    logger.info("%s Expired grant tokens deleted", grants_deleted_no)


def redirect_to_uri_allowed(uri, allowed_uris):
    """
    Checks if a given uri can be redirected to based on the provided allowed_uris configuration.

    On top of exact matches, this function also handles loopback IPs based on RFC 8252.

    :param uri: URI to check
    :param allowed_uris: A list of URIs that are allowed
    """

    if not isinstance(allowed_uris, list):
        raise ValueError("allowed_uris must be a list")

    parsed_uri = urlparse(uri)
    uqs_set = set(parse_qsl(parsed_uri.query))
    for allowed_uri in allowed_uris:
        parsed_allowed_uri = urlparse(allowed_uri)

        if parsed_allowed_uri.scheme != parsed_uri.scheme:
            # match failed, continue
            continue

        """ check hostname """
        if oauth2_settings.ALLOW_URI_WILDCARDS and parsed_allowed_uri.hostname.startswith("*"):
            """ wildcard hostname """
            if not parsed_uri.hostname.endswith(parsed_allowed_uri.hostname[1:]):
                continue
        elif parsed_allowed_uri.hostname != parsed_uri.hostname:
            continue

        # From RFC 8252 (Section 7.3)
        # https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
        #
        # Loopback redirect URIs use the "http" scheme
        # [...]
        # The authorization server MUST allow any port to be specified at the
        # time of the request for loopback IP redirect URIs, to accommodate
        # clients that obtain an available ephemeral port from the operating
        # system at the time of the request.
        allowed_uri_is_loopback = parsed_allowed_uri.scheme == "http" and parsed_allowed_uri.hostname in [
            "127.0.0.1",
            "::1",
        ]
        """ check port """
        if not allowed_uri_is_loopback and parsed_allowed_uri.port != parsed_uri.port:
            continue

        """ check path """
        if parsed_allowed_uri.path != parsed_uri.path:
            continue

        """ check querystring """
        aqs_set = set(parse_qsl(parsed_allowed_uri.query))
        if not aqs_set.issubset(uqs_set):
            continue  # circuit break

        return True

    # if uris matched then it's not allowed
    return False


def is_origin_allowed(origin, allowed_origins):
    """
    Checks if a given origin uri is allowed based on the provided allowed_origins configuration.

    :param origin: Origin URI to check
    :param allowed_origins: A list of Origin URIs that are allowed
    """

    parsed_origin = urlparse(origin)

    if parsed_origin.scheme not in oauth2_settings.ALLOWED_SCHEMES:
        return False

    for allowed_origin in allowed_origins:
        parsed_allowed_origin = urlparse(allowed_origin)
        if (
            parsed_allowed_origin.scheme == parsed_origin.scheme
            and parsed_allowed_origin.netloc == parsed_origin.netloc
        ):
            return True

    return False
