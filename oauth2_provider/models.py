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
from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import ImproperlyConfigured
from django.db import models, router, transaction
from django.dispatch import receiver
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
        help_text=_("Client secret for authentication"),
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


class AbstractSession(models.Model):
    """
    A Session instance represents an OpenID Connect authentication session:
    the continuous period during which an End-User is authenticated at this
    authorization server via a particular user agent, as defined by
    `OpenID Connect Back-Channel Logout 1.0
    <https://openid.net/specs/openid-connect-backchannel-1_0.html>`_.

    It is identified by :attr:`sid`, which is issued as the ``sid`` claim in
    ID Tokens. It is correlated with — but distinct from — the Django
    session: the Django session key is the (secret) authentication cookie
    value, while ``sid`` is a public identifier that is safe to hand to
    relying parties.

    Sessions are minted lazily at the first authorization request after
    login and reused for subsequent authorizations from the same user agent,
    so one session spans every application the user signs into during it.

    Fields:

    * :attr:`sid` Public session identifier, issued as the ``sid`` claim
    * :attr:`user` The Django user the session belongs to
    * :attr:`session_key` The Django session key this session was minted
                          under, kept only as a correlation aid
    * :attr:`authenticated_at` When the user authenticated for this session;
                               the source of the ``auth_time`` claim
    * :attr:`expires` When the session expires
    * :attr:`terminated_at` Timestamp of when this session was terminated
    * :attr:`termination_reason` Why the session was terminated
    """

    TERMINATION_LOGOUT = "logout"
    TERMINATION_RP_LOGOUT = "rp_logout"
    TERMINATION_EXPIRED = "expired"
    TERMINATION_ADMIN = "admin"
    TERMINATION_REASONS = (
        (TERMINATION_LOGOUT, _("Logout")),
        (TERMINATION_RP_LOGOUT, _("RP-Initiated Logout")),
        (TERMINATION_EXPIRED, _("Expired")),
        (TERMINATION_ADMIN, _("Terminated by admin")),
    )

    id = models.BigAutoField(primary_key=True)
    sid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_%(class)s",
    )
    session_key = models.CharField(max_length=40, blank=True, default="", db_index=True)
    authenticated_at = models.DateTimeField()
    expires = models.DateTimeField()

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    terminated_at = models.DateTimeField(null=True, blank=True)
    termination_reason = models.CharField(max_length=32, blank=True, default="", choices=TERMINATION_REASONS)

    def is_expired(self):
        """
        Check session expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def is_active(self):
        return self.terminated_at is None and not self.is_expired()

    def terminate(self, reason=""):
        """
        Mark this session terminated. Termination is the session axis: it
        records that this user agent's authentication ended. It does not, by
        itself, revoke authorizations or tokens.
        """
        if self.terminated_at is not None:
            return
        self.terminated_at = timezone.now()
        self.termination_reason = reason
        self.save(update_fields=["terminated_at", "termination_reason", "updated"])

    def __str__(self):
        return "SID: {self.sid} User: {self.user_id}".format(self=self)

    class Meta:
        abstract = True


class Session(AbstractSession):
    class Meta(AbstractSession.Meta):
        swappable = "OAUTH2_PROVIDER_SESSION_MODEL"


class AbstractAuthorization(models.Model):
    """
    An Authorization instance is a durable record of an authorization grant:
    the fact that a user (or a confidential client acting on its own behalf)
    authorized an Application for a set of scopes at a point in time, via a
    particular grant type.

    :rfc:`6749 <1.3>` defines an authorization grant as the *credential*
    representing the resource owner's authorization (the authorization code,
    the resource owner's password, the client's own credentials, the device
    code, ...). Those credentials are transient and flow-specific; this model
    records the durable fact they all represent, so that every token can be
    traced back to the act of consent that produced it, whichever flow issued
    it.

    Tokens issued under an authorization reference it; revoking an
    authorization revokes every token issued under it, on every device.

    Deletion is not a domain action — :meth:`revoke` is. The token foreign
    keys are ``RESTRICT``, so an authorization cannot be deleted while tokens
    issued under it exist (except through a cascade that is deleting those
    tokens too, e.g. deleting the user or the application). Row deletion is
    reserved for cleanup (``cleartokens``) once every token is gone.

    Fields:

    * :attr:`user` The Django user who granted the authorization. NULL for
                   ``client_credentials``, where the "consent" is the client
                   registration itself.
    * :attr:`application` Application instance the authorization was granted to
    * :attr:`session` The authentication session the authorization was
                      granted during. NULL for non-interactive flows (ROPC,
                      ``client_credentials``) and for offline artifacts that
                      predate session tracking.
    * :attr:`grant_type` How the authorization was expressed (one of
                         :attr:`AbstractApplication.GRANT_TYPES`)
    * :attr:`scope` Scopes granted, space separated
    * :attr:`revoked_at` Timestamp of when this authorization was revoked
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
    )
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE)
    session = models.ForeignKey(
        oauth2_settings.SESSION_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
    )
    grant_type = models.CharField(max_length=44, choices=AbstractApplication.GRANT_TYPES)
    scope = models.TextField(blank=True)

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def is_active(self):
        return self.revoked_at is None

    def allow_scopes(self, scopes):
        """
        Check if the authorization covers the provided scopes

        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def revoke(self):
        """
        Revoke this authorization: every token issued under it, and every
        outstanding credential (unexchanged authorization code, approved but
        not yet redeemed device grant) that could still mint tokens under it.

        This is the consent axis: it kills the authorization's token chains
        everywhere, but it does not log anyone out.
        """
        access_token_model = get_access_token_model()
        refresh_token_model = get_refresh_token_model()
        id_token_model = get_id_token_model()
        grant_model = get_grant_model()
        device_grant_model = get_device_grant_model()

        # Use the AccessToken's database instead of making the assumption it is in 'default'.
        with transaction.atomic(using=router.db_for_write(access_token_model)):
            if self.revoked_at is None:
                self.revoked_at = timezone.now()
                self.save(update_fields=["revoked_at", "updated"])

            # Close the paths that could still issue tokens under this
            # authorization: codes not yet exchanged and devices approved but
            # not yet redeemed. Exchanged codes are kept as replay evidence.
            grant_model.objects.filter(authorization=self, exchanged_at__isnull=True).delete()
            device_grant_model.objects.filter(
                authorization=self, status=device_grant_model.AUTHORIZED
            ).update(status=device_grant_model.DENIED)

            for refresh_token in refresh_token_model.objects.filter(authorization=self, revoked__isnull=True):
                refresh_token.revoke()
            for access_token in access_token_model.objects.filter(authorization=self):
                access_token.revoke()
            for id_token in id_token_model.objects.filter(authorization=self):
                id_token.revoke()

    def __str__(self):
        return "Application: {self.application_id} User: {self.user_id} Grant type: {self.grant_type}".format(
            self=self
        )

    class Meta:
        abstract = True


class Authorization(AbstractAuthorization):
    class Meta(AbstractAuthorization.Meta):
        swappable = "OAUTH2_PROVIDER_AUTHORIZATION_MODEL"


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
    * :attr:`authorization` The Authorization this code was issued under
    * :attr:`exchanged_at` Timestamp of when this code was exchanged for
                           tokens. A code presented again after this is set is
                           a replay: :rfc:`6749 <4.1.2>` calls for revoking the
                           tokens previously issued on it.
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

    authorization = models.ForeignKey(
        oauth2_settings.AUTHORIZATION_MODEL,
        # A code is only a claim ticket on its authorization: if the
        # authorization is deleted the code must not remain exchangeable.
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
    )
    exchanged_at = models.DateTimeField(null=True, blank=True)

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
    authorization = models.ForeignKey(
        oauth2_settings.AUTHORIZATION_MODEL,
        # RESTRICT preserves token lineage: an authorization cannot be
        # deleted while tokens issued under it exist, except through a
        # cascade (user/application deletion) that deletes the tokens too.
        # Revocation, not deletion, is the domain action.
        on_delete=models.RESTRICT,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
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
    token = models.TextField()
    token_checksum = TokenChecksumField(
        max_length=64,
        blank=False,
    )
    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE)
    access_token = models.OneToOneField(
        oauth2_settings.ACCESS_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refresh_token",
    )
    authorization = models.ForeignKey(
        oauth2_settings.AUTHORIZATION_MODEL,
        # RESTRICT preserves token lineage: an authorization cannot be
        # deleted while tokens issued under it exist, except through a
        # cascade (user/application deletion) that deletes the tokens too.
        # Revocation, not deletion, is the domain action.
        on_delete=models.RESTRICT,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
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
                access_token_model.objects.get(pk=self.access_token_id).revoke()

            self.access_token = None
            self.revoked = timezone.now()
            self.save()

    def __str__(self):
        return self.token

    class Meta:
        abstract = True
        unique_together = (
            "token_checksum",
            "revoked",
        )


class RefreshToken(AbstractRefreshToken):
    class Meta(AbstractRefreshToken.Meta):
        swappable = "OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL"


class AbstractIDToken(models.Model):
    """
    An IDToken instance represents the token used to authenticate the user and
    convey claims to the client, as in
    `OpenID Connect Core 1.0 Section 2 <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>`_.

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
    authorization = models.ForeignKey(
        oauth2_settings.AUTHORIZATION_MODEL,
        # RESTRICT preserves token lineage: an authorization cannot be
        # deleted while tokens issued under it exist, except through a
        # cascade (user/application deletion) that deletes the tokens too.
        # Revocation, not deletion, is the domain action.
        on_delete=models.RESTRICT,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
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
    # Uniqueness is enforced by the unique_device_code UniqueConstraint (Meta.constraints);
    # adding unique=True here would create a redundant duplicate index (MySQL warns ER_DUP_INDEX 1831).
    device_code = models.CharField(max_length=100)
    user_code = models.CharField(max_length=100)
    scope = models.TextField(blank=True)
    interval = models.IntegerField(default=5)
    expires = models.DateTimeField()
    status = models.CharField(
        max_length=64, blank=True, choices=DEVICE_FLOW_STATUS, default=AUTHORIZATION_PENDING
    )
    client_id = models.CharField(max_length=100, db_index=True)
    authorization = models.ForeignKey(
        oauth2_settings.AUTHORIZATION_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
    )
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
    user_code: str
    device_code: str
    interval: int
    verification_uri_complete: Optional[Union[str, Callable]] = None


def create_device_grant(
    device_request: DeviceRequest, device_response: DeviceCodeResponse
) -> AbstractDeviceGrant:
    now = datetime.now(tz=dt_timezone.utc)

    return get_device_grant_model().objects.create(
        client_id=device_request.client_id,
        device_code=device_response.device_code,
        user_code=device_response.user_code,
        scope=device_request.scope or "",
        expires=now + timedelta(seconds=device_response.expires_in),
    )


def get_application_model():
    """Return the Application model that is active in this project."""
    return apps.get_model(oauth2_settings.APPLICATION_MODEL)


def get_authorization_model():
    """Return the Authorization model that is active in this project."""
    return apps.get_model(oauth2_settings.AUTHORIZATION_MODEL)


def get_session_model():
    """Return the Session model that is active in this project."""
    return apps.get_model(oauth2_settings.SESSION_MODEL)


SESSION_SID_KEY = "_oauth2_provider_session_sid"
SESSION_AUTH_TIME_KEY = "_oauth2_provider_auth_time"


@receiver(user_logged_in)
def _remember_auth_time(sender, request, user, **kwargs):
    """
    Record the moment of authentication in the Django session so sessions
    minted later assert an accurate, per-user-agent ``auth_time`` (the
    user-global ``last_login`` is refreshed by logins on *other* devices).
    """
    request.session[SESSION_AUTH_TIME_KEY] = timezone.now().isoformat()


def get_or_create_oauth2_session(request):
    """
    Return the active OP authentication Session for this user agent, minting
    one lazily on the first authorization request after login. The public
    ``sid`` is stored in the Django session so subsequent authorizations from
    the same user agent reuse the same Session.

    Returns None when there is no authenticated user.
    """
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return None

    session_model = get_session_model()

    sid = request.session.get(SESSION_SID_KEY)
    if sid:
        session = session_model.objects.filter(sid=sid, user=request.user, terminated_at__isnull=True).first()
        if session is not None and not session.is_expired():
            return session

    stored_auth_time = request.session.get(SESSION_AUTH_TIME_KEY)
    if stored_auth_time:
        authenticated_at = datetime.fromisoformat(stored_auth_time)
    else:
        authenticated_at = request.user.last_login or timezone.now()

    session = session_model.objects.create(
        user=request.user,
        session_key=request.session.session_key or "",
        authenticated_at=authenticated_at,
        expires=request.session.get_expiry_date(),
    )
    request.session[SESSION_SID_KEY] = str(session.sid)
    return session


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


def get_authorization_admin_class():
    """Return the Authorization admin class that is active in this project."""
    authorization_admin_class = oauth2_settings.AUTHORIZATION_ADMIN_CLASS
    return authorization_admin_class


def get_session_admin_class():
    """Return the Session admin class that is active in this project."""
    session_admin_class = oauth2_settings.SESSION_ADMIN_CLASS
    return session_admin_class


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
            flat_queryset = queryset.values_list("pk", flat=True)[:CLEAR_EXPIRED_TOKENS_BATCH_SIZE]
            batch_length = flat_queryset.count()
            queryset.model.objects.filter(pk__in=list(flat_queryset)).delete()
            logger.debug(f"{batch_length} tokens deleted, {current_no - batch_length} left")
            queryset = queryset.model.objects.filter(query)
            time.sleep(CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL)
            current_no = queryset.count()

        stop_no = queryset.model.objects.filter(query).count()
        deleted = start_no - stop_no
        return deleted

    now = timezone.now()
    refresh_revoked_at = now
    refresh_expire_at = None
    access_token_model = get_access_token_model()
    refresh_token_model = get_refresh_token_model()
    id_token_model = get_id_token_model()
    grant_model = get_grant_model()
    REFRESH_TOKEN_GRACE_PERIOD_SECONDS = oauth2_settings.REFRESH_TOKEN_GRACE_PERIOD_SECONDS
    REFRESH_TOKEN_EXPIRE_SECONDS = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS

    if REFRESH_TOKEN_GRACE_PERIOD_SECONDS:
        try:
            REFRESH_TOKEN_GRACE_PERIOD_SECONDS = timedelta(seconds=REFRESH_TOKEN_GRACE_PERIOD_SECONDS)
        except TypeError:
            e = "REFRESH_TOKEN_GRACE_PERIOD_SECONDS must be in seconds"
            raise ImproperlyConfigured(e)
        if REFRESH_TOKEN_GRACE_PERIOD_SECONDS < timedelta(0):
            e = "REFRESH_TOKEN_GRACE_PERIOD_SECONDS must not be negative"
            raise ImproperlyConfigured(e)
        refresh_revoked_at = now - REFRESH_TOKEN_GRACE_PERIOD_SECONDS

    if REFRESH_TOKEN_EXPIRE_SECONDS:
        if not isinstance(REFRESH_TOKEN_EXPIRE_SECONDS, timedelta):
            try:
                REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
            except TypeError:
                e = "REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds"
                raise ImproperlyConfigured(e)
        refresh_expire_at = now - REFRESH_TOKEN_EXPIRE_SECONDS

    if oauth2_settings.REFRESH_TOKEN_REUSE_PROTECTION:
        # Revoked refresh tokens are what allows reuse of a rotated token to
        # be detected and the token family revoked, so they must be kept
        # until they expire.
        refresh_revoked_at = refresh_expire_at

    if refresh_revoked_at:
        revoked_query = models.Q(revoked__lte=refresh_revoked_at)
        revoked = refresh_token_model.objects.filter(revoked_query)

        revoked_deleted_no = batch_delete(revoked, revoked_query)
        logger.info("%s Revoked refresh tokens deleted", revoked_deleted_no)
    else:
        logger.info("refresh_revoked_at is %s. No revoked refresh tokens deleted.", refresh_revoked_at)

    if refresh_expire_at:
        expired_query = models.Q(access_token__expires__lt=refresh_expire_at)
        expired = refresh_token_model.objects.filter(expired_query)

        expired_deleted_no = batch_delete(expired, expired_query)
        logger.info("%s Expired refresh tokens deleted", expired_deleted_no)
    else:
        logger.info("refresh_expire_at is %s. No expired refresh tokens deleted.", refresh_expire_at)

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

    # Revoked authorizations are only purged once every token issued under
    # them is gone, so token lineage survives for as long as the tokens do.
    authorization_model = get_authorization_model()
    has_no_tokens = (
        ~models.Exists(access_token_model.objects.filter(authorization=models.OuterRef("pk")))
        & ~models.Exists(refresh_token_model.objects.filter(authorization=models.OuterRef("pk")))
        & ~models.Exists(id_token_model.objects.filter(authorization=models.OuterRef("pk")))
    )
    authorizations_query = models.Q(revoked_at__isnull=False) & models.Q(has_no_tokens)
    authorizations = authorization_model.objects.filter(authorizations_query)

    authorizations_deleted_no = batch_delete(authorizations, authorizations_query)
    logger.info("%s Revoked authorizations deleted", authorizations_deleted_no)

    # Ended (terminated or expired) sessions are purged once no authorization
    # references them, so the sid linkage survives for as long as the
    # authorizations granted during the session do.
    session_model = get_session_model()
    has_no_authorizations = ~models.Exists(authorization_model.objects.filter(session=models.OuterRef("pk")))
    sessions_query = (models.Q(terminated_at__isnull=False) | models.Q(expires__lt=now)) & models.Q(
        has_no_authorizations
    )
    sessions = session_model.objects.filter(sessions_query)

    sessions_deleted_no = batch_delete(sessions, sessions_query)
    logger.info("%s Ended sessions deleted", sessions_deleted_no)


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
