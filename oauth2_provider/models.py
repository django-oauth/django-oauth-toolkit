import hashlib
import logging
import time
import uuid
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Callable, Optional, Union
from urllib.parse import urlparse, urlsplit

from django.apps import apps
from django.conf import settings
from django.contrib.auth.hashers import identify_hasher, make_password
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import IntegrityError, models, router, transaction
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


class ResourceJSONField(models.JSONField):
    """
    RFC 8707 - JSON array of resource URIs.

    Empty list means not restricted to specific resource servers (unrestricted access).
    """

    def pre_save(self, model_instance, add):
        """The field is not nullable; treat None as "no resource restriction"."""
        value = super().pre_save(model_instance, add)
        if value is None:
            value = []
            setattr(model_instance, self.attname, value)
        return value

    def get_db_prep_value(self, value, connection, prepared=False):
        """Validate before saving to database."""
        if value is not None:
            if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
                raise ValidationError("Resource must be a list of URI strings")
        return super().get_db_prep_value(value, connection, prepared)


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
        # RFC 9700 token storage: when the plaintext token is redacted at rest (see
        # COMPLIANT_BCP_RFC9700_TOKEN_STORAGE) the raw token is stashed
        # on ``_raw_token`` and the ``token`` column is left blank. The lookup checksum
        # is then computed from ``_raw_token``, which is cleared afterwards to minimize
        # the in-memory lifetime of a usable token value.
        raw_token = getattr(model_instance, "_raw_token", None)
        if raw_token is None:
            # No raw token available. On the plaintext-storage path the ``token``
            # column holds the raw token, so (re)derive the checksum from it. On the
            # hashed-at-rest path the column is blank on later saves (e.g.
            # ``RefreshToken.revoke()``); there is nothing to recompute, so the
            # existing checksum is kept instead of being hashed a second time.
            token = getattr(model_instance, "token")
            if not token:
                return super().pre_save(model_instance, add)
            raw_token = token
        else:
            model_instance._raw_token = None
        checksum = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        setattr(model_instance, self.attname, checksum)
        return super().pre_save(model_instance, add)


def set_token_value(token_instance: "AbstractAccessToken | AbstractRefreshToken", raw_token: str) -> None:
    """
    Assign the raw token to a token instance, redacting the value stored at rest
    when COMPLIANT_BCP_RFC9700_TOKEN_STORAGE is enabled (RFC 9700).

    The lookup checksum (``token_checksum``) is always derived from the raw token;
    when redacting, the raw value is stashed on ``_raw_token`` (used only to compute
    the checksum, see :class:`TokenChecksumField`) and the ``token`` column is left
    blank so the reusable token is never persisted.

    Plaintext storage is an ambient config posture exercised on every token
    issuance, so (unlike the request-time gates) it is surfaced by the ``--deploy``
    system check ``W006`` rather than a per-token warning here. See
    :mod:`oauth2_provider.bcp`.
    """
    if oauth2_settings.COMPLIANT_BCP_RFC9700_TOKEN_STORAGE:
        token_instance._raw_token = raw_token
        token_instance.token = ""
    else:
        token_instance.token = raw_token
        # Clear any stale redaction marker so a later save recomputes the checksum
        # from this plaintext token rather than a previously stashed raw value.
        token_instance._raw_token = None


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
    * :attr:`registration_source` How the Application was registered: ``manual``
                                  for manually created Applications, ``dcr`` for
                                  those registered via Dynamic Client
                                  Registration (RFC 7591), ``cimd`` for Client
                                  ID Metadata Document
    * :attr:`cimd_expires_at` When the cached metadata document should be
                              re-fetched, for CIMD applications
    """

    class RegistrationSource(models.TextChoices):
        MANUAL = "manual", _("Manual")
        DCR = "dcr", _("Dynamic Client Registration")
        CIMD = "cimd", _("Client ID Metadata Document")
        # FEDERATION (OpenID Federation) reserved for future use

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
    # 255 rather than 100 so a Client ID Metadata Document URL fits (CIMD uses
    # the client's https URL as its client_id).
    client_id = models.CharField(
        max_length=255, unique=True, default=generate_client_id, db_index=True, verbose_name=_("client ID")
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="%(app_label)s_%(class)s",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        verbose_name=_("user"),
    )

    redirect_uris = models.TextField(
        blank=True,
        help_text=_("Allowed URIs list, space separated"),
        verbose_name=_("redirect URIs"),
    )
    post_logout_redirect_uris = models.TextField(
        blank=True,
        help_text=_("Allowed Post Logout URIs list, space separated"),
        default="",
        verbose_name=_("post logout redirect URIs"),
    )
    client_type = models.CharField(max_length=32, choices=CLIENT_TYPES, verbose_name=_("client type"))
    authorization_grant_type = models.CharField(
        max_length=44, choices=GRANT_TYPES, verbose_name=_("authorization grant type")
    )
    client_secret = ClientSecretField(
        max_length=255,
        blank=True,
        default=generate_client_secret,
        db_index=True,
        help_text=_("Client secret for authentication"),
        verbose_name=_("client secret"),
    )
    hash_client_secret = models.BooleanField(default=True, verbose_name=_("hash client secret"))
    name = models.CharField(max_length=255, blank=True, verbose_name=_("name"))
    skip_authorization = models.BooleanField(default=False, verbose_name=_("skip authorization"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))
    algorithm = models.CharField(
        max_length=5, choices=ALGORITHM_TYPES, default=NO_ALGORITHM, blank=True, verbose_name=_("algorithm")
    )
    allowed_origins = models.TextField(
        blank=True,
        help_text=_("Allowed origins list to enable CORS, space separated"),
        default="",
        verbose_name=_("allowed origins"),
    )
    registration_source = models.CharField(
        max_length=32,
        choices=RegistrationSource.choices,
        default=RegistrationSource.MANUAL,
        help_text=_("How this application was registered (manual, DCR per RFC 7591, or CIMD)"),
        verbose_name=_("registration source"),
    )
    cimd_expires_at = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text=_("When the cached Client ID Metadata Document should be re-fetched"),
        verbose_name=_("CIMD expires at"),
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

        # No redirect_uris registered (e.g. a client_credentials application used
        # in a flow that requires one). Raise an oauthlib error so the endpoint
        # returns a spec-compliant 400 instead of an uncaught AssertionError/500
        # (the assert would also be stripped entirely under `python -O`). See #958.
        raise errors.MissingRedirectURIError()

    def redirect_uri_allowed(self, uri: str) -> bool:
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """
        allowed, reasons = check_redirect_to_uri_allowed(uri, self.redirect_uris.split())
        if not allowed:
            _log_registered_uri_mismatch("redirect_uri", uri, self.client_id, reasons)
        return allowed

    def post_logout_redirect_uri_allowed(self, uri: str) -> bool:
        """
        Checks if given URI is one of the items in :attr:`post_logout_redirect_uris` string

        :param uri: URI to check
        """
        allowed, reasons = check_redirect_to_uri_allowed(uri, self.post_logout_redirect_uris.split())
        if not allowed:
            _log_registered_uri_mismatch("post_logout_redirect_uri", uri, self.client_id, reasons)
        return allowed

    def origin_allowed(self, origin):
        """
        Checks if given origin is one of the items in :attr:`allowed_origins` string

        :param origin: Origin to check
        """
        return self.allowed_origins and is_origin_allowed(origin, self.allowed_origins.split())

    def clean(self) -> None:
        """Validate the application, reporting each problem on the field it belongs to.

        Raises a :class:`~django.core.exceptions.ValidationError` keyed by field name, so
        callers get a per-field ``message_dict`` and a ModelForm renders each message next
        to its input. Every problem found is reported, not just the first one.
        """
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

        # Errors are keyed by the field they belong to and raised together at the end,
        # rather than raised one at a time as they are found. Keying them means
        # ``full_clean()`` reports them per field (``ValidationError.message_dict``) and a
        # ModelForm -- the admin and the built-in application views both use one -- renders
        # each message next to the offending input instead of as an anonymous non-field
        # error at the top of the form. Collecting them means a single submit reports every
        # problem at once instead of one per round trip.
        field_errors = defaultdict(list)

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
                try:
                    validator(uri)
                except ValidationError as exc:
                    field_errors["redirect_uris"].extend(exc.error_list)

        elif self.authorization_grant_type in grant_types:
            field_errors["redirect_uris"].append(
                ValidationError(
                    _("redirect_uris cannot be empty with grant_type {grant_type}").format(
                        grant_type=self.authorization_grant_type
                    )
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
                try:
                    validator(uri)
                except ValidationError as exc:
                    field_errors["allowed_origins"].extend(exc.error_list)

        if self.algorithm == AbstractApplication.RS256_ALGORITHM:
            if not oauth2_settings.OIDC_RSA_PRIVATE_KEY:
                field_errors["algorithm"].append(
                    ValidationError(_("You must set OIDC_RSA_PRIVATE_KEY to use RSA algorithm"))
                )

        if self.algorithm == AbstractApplication.HS256_ALGORITHM:
            if any(
                (
                    self.authorization_grant_type in hs_forbidden_grant_types,
                    self.client_type == Application.CLIENT_PUBLIC,
                )
            ):
                field_errors["algorithm"].append(
                    ValidationError(_("You cannot use HS256 with public grants or clients"))
                )
            if not self.client_secret:
                field_errors["client_secret"].append(
                    ValidationError(
                        _("You cannot use HS256 without a client secret; it is the HMAC signing key.")
                    )
                )
            # For HS256 the client secret is the shared HMAC signing key, so it must be stored
            # unhashed. Reject both the intent to hash (the flag) and an already-hashed stored
            # value (e.g. the flag was toggled after the secret was hashed, or a legacy row), so
            # the misconfiguration surfaces here instead of only failing later at signing time.
            # The error goes on whichever field has to change: the flag when it is still set,
            # otherwise the already-hashed secret itself, which has to be re-entered unhashed.
            elif self.hash_client_secret or self._client_secret_is_hashed(self.client_secret):
                field_errors["hash_client_secret" if self.hash_client_secret else "client_secret"].append(
                    ValidationError(
                        _(
                            "You cannot use HS256 with a hashed client secret. For HS256 the client "
                            "secret is the shared signing key and must be stored unhashed so the relying "
                            "party can verify the token; set hash_client_secret=False and store an "
                            "unhashed client_secret on this application."
                        )
                    )
                )

        if field_errors:
            raise ValidationError(field_errors)

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

    @staticmethod
    def _client_secret_is_hashed(client_secret):
        """Return True if the stored client secret is a Django password hash."""
        try:
            identify_hasher(client_secret)
        except ValueError:
            return False
        return True

    @property
    def jwk_key(self):
        if self.algorithm == AbstractApplication.RS256_ALGORITHM:
            if not oauth2_settings.OIDC_RSA_PRIVATE_KEY:
                raise ImproperlyConfigured("You must set OIDC_RSA_PRIVATE_KEY to use RSA algorithm")
            return jwk_from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY)
        elif self.algorithm == AbstractApplication.HS256_ALGORITHM:
            # An empty secret would sign tokens with an empty HMAC key, which is trivially
            # forgeable by anyone.
            if not self.client_secret:
                raise ImproperlyConfigured(
                    "HS256 signing requires a non-empty client secret to use as the HMAC key."
                )
            # A hashed secret would sign tokens with the password hash string as the HMAC key,
            # which the relying party (holding the plaintext secret) can never verify.
            if self._client_secret_is_hashed(self.client_secret):
                raise ImproperlyConfigured(
                    "HS256 signing requires the plaintext client secret as the HMAC key, but this "
                    "application's client secret is hashed. Set hash_client_secret=False and reset "
                    "the client_secret (or recreate the application) so the plaintext secret is stored."
                )
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
    * :attr:`resource` RFC 8707 resource indicator(s), JSON-encoded array of URIs
    """

    CODE_CHALLENGE_PLAIN = "plain"
    CODE_CHALLENGE_S256 = "S256"
    CODE_CHALLENGE_METHODS = ((CODE_CHALLENGE_PLAIN, "plain"), (CODE_CHALLENGE_S256, "S256"))

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_%(class)s",
        verbose_name=_("user"),
    )
    code = models.CharField(max_length=255, unique=True, verbose_name=_("code"))  # code comes from oauthlib
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE, verbose_name=_("application")
    )
    expires = models.DateTimeField(verbose_name=_("expires"))
    redirect_uri = models.TextField(verbose_name=_("redirect URI"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))

    code_challenge = models.CharField(
        max_length=128, blank=True, default="", verbose_name=_("code challenge")
    )
    code_challenge_method = models.CharField(
        max_length=10,
        blank=True,
        default="",
        choices=CODE_CHALLENGE_METHODS,
        verbose_name=_("code challenge method"),
    )

    nonce = models.CharField(max_length=255, blank=True, default="", verbose_name=_("nonce"))
    claims = models.TextField(blank=True, verbose_name=_("claims"))

    resource = ResourceJSONField(blank=True, default=list, verbose_name=_("resource"))

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def redirect_uri_allowed(self, uri: str) -> bool:
        allowed = uri == self.redirect_uri
        if not allowed and logger.isEnabledFor(logging.DEBUG):
            # Never log self.code alongside this: an authorization code in a log
            # file is a credential, which is why __str__ below omits it too.
            logger.debug(
                "redirect_uri %s does not match the redirect_uri %s recorded on grant #%s at "
                "authorization time; RFC 6749 section 4.1.3 requires them to be identical",
                _loggable_uri(uri),
                _loggable_uri(self.redirect_uri),
                self.pk,
            )
        return allowed

    def __str__(self):
        # Never render the authorization code itself: __str__ appears in the admin
        # change page/breadcrumbs, in repr() within tracebacks, and in log output.
        return "Grant #{self.pk}".format(self=self)

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
    * :attr:`resource` RFC 8707 resource indicator(s) - JSON-encoded array of URIs
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="%(app_label)s_%(class)s",
        verbose_name=_("user"),
    )
    source_refresh_token = models.OneToOneField(
        # unique=True implied by the OneToOneField
        oauth2_settings.REFRESH_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refreshed_access_token",
        verbose_name=_("source refresh token"),
    )
    token = models.TextField(verbose_name=_("token"))
    token_checksum = TokenChecksumField(
        max_length=64,
        blank=False,
        unique=True,
        db_index=True,
        verbose_name=_("token checksum"),
    )
    id_token = models.OneToOneField(
        oauth2_settings.ID_TOKEN_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        related_name="access_token",
        verbose_name=_("ID token"),
    )
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_("application"),
    )

    expires = models.DateTimeField(verbose_name=_("expires"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))

    resource = ResourceJSONField(blank=True, default=list, verbose_name=_("resource"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))

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

    def allows_audience(self, audience_uri):
        """
        Check if the token is authorized for the given audience URI.

        RFC 8707: Validates that the token includes the specified resource indicator
        using the configured resource validator (RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR).

        If the token has no resource indicators (empty list), it is unrestricted and
        allows any audience (backward compatibility).

        :param audience_uri: The URI of the resource server to check
        :return: True if the token is authorized for this audience, False otherwise
        """
        audiences = self.resource
        if not audiences:
            # No resource indicators - unrestricted token allows any audience,
            # regardless of how a custom validator treats an empty list.
            return True

        resource_validator = oauth2_settings.RESOURCE_SERVER_TOKEN_RESOURCE_VALIDATOR

        if resource_validator:
            return resource_validator(audience_uri, audiences)
        else:
            # No validator configured - allow everything (backward compat)
            return True

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
        # Never render the token itself: __str__ appears in the admin change
        # page/breadcrumbs, in repr() within tracebacks, and in log output.
        return "AccessToken #{self.pk}".format(self=self)

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
    * :attr:`resource` RFC 8707 resource indicator(s), JSON-encoded array of URIs
    """

    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_%(class)s",
        verbose_name=_("user"),
    )
    token = models.TextField(verbose_name=_("token"))
    token_checksum = TokenChecksumField(
        max_length=64,
        blank=False,
        verbose_name=_("token checksum"),
    )
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE, verbose_name=_("application")
    )
    access_token = models.OneToOneField(
        oauth2_settings.ACCESS_TOKEN_MODEL,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="refresh_token",
        verbose_name=_("access token"),
    )
    token_family = models.UUIDField(null=True, blank=True, editable=False, verbose_name=_("token family"))

    resource = ResourceJSONField(blank=True, default=list, verbose_name=_("resource"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))
    revoked = models.DateTimeField(null=True, verbose_name=_("revoked"))

    @classmethod
    def revoke_family(cls, token_family: uuid.UUID | None) -> None:
        """
        Revoke every live refresh token sharing ``token_family`` and delete the family's
        access tokens, in a constant number of queries.

        This is the set-based equivalent of calling :meth:`revoke` on each member of the
        family, which is what reuse protection needs: a rotating client adds a row to its
        family on every refresh, so revoking row by row cost one ``SELECT ... FOR UPDATE``
        round trip per token ever issued to that session, paid again on every replay of the
        stale token (#1809). A model that overrides :meth:`revoke` to do more should
        override this too.

        Rows are not locked up front: unlike rotation this path mints nothing, so there is
        no read-then-write to protect. The statements take their locks in the same order as
        :meth:`revoke` -- refresh token, then access token -- so a concurrent rotation in
        the family cannot deadlock against the sweep.

        Falls back to revoking row by row if the bulk write hits the uniqueness of
        ``(token_checksum, revoked)``; see the handler below and #1816.
        """
        if not token_family:
            return

        access_token_model = get_access_token_model()
        access_token_database = router.db_for_write(access_token_model)

        try:
            with transaction.atomic(using=access_token_database):
                now = timezone.now()
                # ``updated`` is ``auto_now``, which a queryset update does not trigger.
                cls.objects.filter(token_family=token_family, revoked__isnull=True).update(
                    revoked=now, updated=now
                )
                # Deleting is what ``AccessToken.revoke()`` does, and ``access_token`` is
                # ``SET_NULL``, so this clears the pointer on the rows revoked above as well.
                # The family is re-read rather than snapshotted before the update, so a member
                # rotated in concurrently loses its access token too and is left an orphan,
                # which ``validate_refresh_token`` rejects. Sub-selecting through the forward
                # FK avoids the reverse accessor, whose name a swapped model may change.
                access_token_model.objects.filter(
                    pk__in=cls.objects.filter(token_family=token_family).values("access_token_id")
                ).delete()
        except IntegrityError:
            # Uniqueness is ``(token_checksum, revoked)``, so one shared timestamp cannot
            # cover two live members holding the same checksum -- a state the constraint
            # ought to forbid outright but does not, since NULLs compare distinct and live
            # rows have ``revoked`` NULL (#1816). Reuse detection must not raise on the way
            # to ``invalid_grant``, so fall back to the pre-#1809 sweep, which gives every
            # row its own ``timezone.now()``. This costs a locking SELECT per family member
            # again, but only for a family that is already in a state it cannot reach by
            # rotating: the ``revoke()`` per row is the whole point of the fallback.
            # Delete once #1816 takes ``revoked`` out of the unique key.
            for related_rt in cls.objects.filter(token_family=token_family):
                related_rt.revoke()

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
        # Never render the token itself: __str__ appears in the admin change
        # page/breadcrumbs, in repr() within tracebacks, and in log output.
        return "RefreshToken #{self.pk}".format(self=self)

    class Meta:
        abstract = True
        unique_together = (
            "token_checksum",
            "revoked",
        )
        indexes = [
            # ``revoke_family()`` filters on ``token_family`` on the ``/token/`` path,
            # and without an index that is a scan of the whole refresh token table.
            models.Index(fields=["token_family"]),
        ]


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
        verbose_name=_("user"),
    )
    jti = models.UUIDField(unique=True, default=uuid.uuid4, editable=False, verbose_name=_("JWT Token ID"))
    application = models.ForeignKey(
        oauth2_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        blank=True,
        null=True,
        verbose_name=_("application"),
    )
    expires = models.DateTimeField(verbose_name=_("expires"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))

    created = models.DateTimeField(auto_now_add=True, verbose_name=_("created"))
    updated = models.DateTimeField(auto_now=True, verbose_name=_("updated"))

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
        verbose_name=_("user"),
    )
    # Uniqueness is enforced by the unique_device_code UniqueConstraint (Meta.constraints);
    # adding unique=True here would create a redundant duplicate index (MySQL warns ER_DUP_INDEX 1831).
    device_code = models.CharField(max_length=100, verbose_name=_("device code"))
    user_code = models.CharField(max_length=100, verbose_name=_("user code"))
    scope = models.TextField(blank=True, verbose_name=_("scope"))
    interval = models.IntegerField(default=5, verbose_name=_("interval"))
    expires = models.DateTimeField(verbose_name=_("expires"))
    status = models.CharField(
        max_length=64,
        blank=True,
        choices=DEVICE_FLOW_STATUS,
        default=AUTHORIZATION_PENDING,
        verbose_name=_("status"),
    )
    client_id = models.CharField(max_length=100, db_index=True, verbose_name=_("client ID"))
    last_checked = models.DateTimeField(auto_now=True, verbose_name=_("last checked"))

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


def refresh_token_expire_timedelta():
    """Return ``REFRESH_TOKEN_EXPIRE_SECONDS`` as a ``timedelta``, or ``None`` when refresh
    tokens do not age-expire (the setting is unset, ``0``, or ``timedelta(0)``).

    Raises ``ImproperlyConfigured`` for a non-numeric, out-of-range, or negative value
    (like ``REFRESH_TOKEN_GRACE_PERIOD_SECONDS``) so that both the validation-time
    enforcement and ``clear_expired`` fail the same way on a misconfiguration instead of
    raising an opaque ``TypeError``/``OverflowError``.
    """
    value = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS
    if not value:
        return None
    if not isinstance(value, timedelta):
        try:
            value = timedelta(seconds=value)
        except (TypeError, OverflowError):
            raise ImproperlyConfigured("REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds")
    if value < timedelta(0):
        raise ImproperlyConfigured("REFRESH_TOKEN_EXPIRE_SECONDS must not be negative")
    return value


def revoke_access_token(access_token: AbstractAccessToken) -> None:
    """
    Revoke an access token and, if present, its bound refresh token.

    Deleting the access token on its own leaves the refresh token usable (the
    ``RefreshToken.access_token`` FK is ``SET_NULL``), so it can still be exchanged for a fresh
    access token, defeating the revocation. Per :rfc:`7009#section-2.1` revoking an access token
    MAY also revoke the bound refresh token; revoking the refresh token also deletes the bound
    access token, so it covers both. When there is no refresh token, revoke the access token
    directly (which deletes it).

    The bound refresh token is looked up with a forward query on the refresh token model rather
    than the reverse ``access_token.refresh_token`` accessor, whose name depends on the
    ``related_name`` a swapped refresh token model may override.

    This is the single revoke path shared by the ``/revoke/`` endpoint, the
    ``AuthorizedTokenDeleteView``, and the admin "Revoke selected access tokens" action. Whether a
    refresh token may *survive* access-token revocation is a policy deferred to 4.x (see #1786).
    """
    refresh_token = get_refresh_token_model().objects.filter(access_token=access_token).first()
    if refresh_token is not None:
        refresh_token.revoke()
    else:
        access_token.revoke()


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

    refresh_token_expire_delta = refresh_token_expire_timedelta()
    if refresh_token_expire_delta:
        refresh_expire_at = now - refresh_token_expire_delta

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

    # Orphaned refresh tokens: non-revoked, but their access token is gone
    # (``RefreshToken.access_token`` is SET_NULL, so deleting an access token out of band
    # leaves the refresh token behind with a NULL FK). The toolkit no longer produces
    # these -- both the RFC 7009 ``/revoke/`` endpoint and the admin view revoke the bound
    # refresh token when an access token is revoked -- so any that remain came from an
    # out-of-band deletion and are stale. Delete them regardless of
    # REFRESH_TOKEN_EXPIRE_SECONDS: there is no access token to anchor an expiry on, and a
    # surviving orphan could re-mint access tokens, defeating whatever removed the access
    # token in the first place. This is also the case that could previously live in the DB
    # forever, because the age join below can never match a NULL access token (#746).
    orphan_query = models.Q(revoked__isnull=True, access_token__isnull=True)
    orphans = refresh_token_model.objects.filter(orphan_query)

    orphans_deleted_no = batch_delete(orphans, orphan_query)
    logger.info("%s Orphaned refresh tokens deleted", orphans_deleted_no)

    if refresh_expire_at:
        # Idle expiry: a refresh token is reclaimed REFRESH_TOKEN_EXPIRE_SECONDS after its
        # paired access token expires. ``access_token.expires`` advances on every refresh,
        # so an actively-used token slides forward and only dormant ones are reaped. Orphans
        # (NULL access token) are handled above; this join deliberately ignores them.
        # ``__lte`` so a token whose access token expired exactly at the cutoff is reclaimed,
        # matching AccessToken.is_expired() (``now >= expires``) and validation-time expiry.
        expired_query = models.Q(revoked__isnull=True, access_token__expires__lte=refresh_expire_at)
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


# Neither side of the comparison is trusted to be bounded.  The requested URI is
# client input, and the registered URIs only look like operator configuration: under
# RFC 7591 dynamic registration and CIMD they are supplied by the registrant, and
# neither path caps their length or their number.  256 characters is well past any
# legitimate redirect URI, and 10 candidates past any legitimate client, while both
# stay short enough that a flood of junk cannot fill the log.
_MAX_LOGGED_URI_LENGTH = 256
_MAX_LOGGED_CANDIDATES = 10


def _loggable_uri(uri: Optional[str]) -> str:
    """
    Render a client-supplied URI for inclusion in a log message.

    The value is truncated, and rendered with ``repr()`` so that control
    characters -- CR/LF above all -- are escaped rather than forging log lines.

    :param uri: URI to render
    """
    if uri is None:
        return "None"
    if len(uri) > _MAX_LOGGED_URI_LENGTH:
        uri = uri[:_MAX_LOGGED_URI_LENGTH] + "...[truncated]"
    return repr(uri)


def _format_uri_mismatch_reasons(reasons: list[tuple[Optional[str], str]]) -> str:
    """
    Render the reasons collected by :func:`check_redirect_to_uri_allowed` as one
    log-friendly string.

    Candidates are rendered through :func:`_loggable_uri` for the same reason the
    requested URI is: a registered URI can be registrant-supplied and unbounded.

    :param reasons: ``(candidate, reason)`` pairs; a ``None`` candidate is a
        rejection of the requested URI itself rather than of a registered one
    """
    if not reasons:
        return "no URIs are registered"
    listed = "; ".join(
        reason if candidate is None else "{0}: {1}".format(_loggable_uri(candidate), reason)
        for candidate, reason in reasons[:_MAX_LOGGED_CANDIDATES]
    )
    remaining = len(reasons) - _MAX_LOGGED_CANDIDATES
    if remaining > 0:
        listed += "; ...and {0} further registered URI(s) not listed".format(remaining)
    return listed


def _log_registered_uri_mismatch(
    uri_type: str, uri: str, client_id: str, reasons: list[tuple[Optional[str], str]]
) -> None:
    """
    Log why a client-supplied URI matched none of the URIs registered for a client.

    Without this the mismatch reaches the developer as nothing but oauthlib's bare
    "Mismatching redirect URI." (see #681).  The detail is deliberately confined to
    the log and must never be added to the error response: that response is
    rendered to whoever made the request, so it would let an unauthenticated caller
    read back a client's registered URIs by sending a junk URI with a known
    client_id.

    :param uri_type: name of the parameter being checked, for the log message
    :param uri: the client-supplied URI that was rejected
    :param client_id: client whose registered URIs were checked
    :param reasons: ``(candidate, reason)`` pairs from :func:`check_redirect_to_uri_allowed`
    """
    if not logger.isEnabledFor(logging.DEBUG):
        return
    logger.debug(
        "%s %s does not match any %s registered for client_id %r: %s",
        uri_type,
        _loggable_uri(uri),
        uri_type,
        client_id,
        _format_uri_mismatch_reasons(reasons),
    )


def check_redirect_to_uri_allowed(
    uri: str, allowed_uris: list[str]
) -> tuple[bool, list[tuple[Optional[str], str]]]:
    """
    Same check as :func:`redirect_to_uri_allowed`, additionally reporting why the
    URI was rejected.

    Returns ``(allowed, reasons)``.  ``reasons`` is only meaningful when
    ``allowed`` is ``False``: it holds one ``(candidate, reason)`` pair for every
    registered URI that failed to match, plus pairs with a ``None`` candidate for
    rejections of the requested URI itself.  A reason names the component that
    differs instead of echoing the requested URI back, which callers log once and
    only after passing it through :func:`_loggable_uri`.

    :param uri: URI to check
    :param allowed_uris: A list of URIs that are allowed
    """

    if not isinstance(allowed_uris, list):
        raise ValueError("allowed_uris must be a list")

    reasons: list[tuple[Optional[str], str]] = []

    # urlsplit() rather than urlparse(): urlparse() peels ";params" off the last
    # path segment into a separate attribute, so comparing .path alone would let a
    # request smuggle "/cb;evil=1" past a registered "/cb".  urlsplit() leaves the
    # parameters in .path, where they are compared like the rest of it.
    parsed_uri = urlsplit(uri)

    # RFC 6749 section 3.1.2: "The endpoint URI MUST NOT include a fragment
    # component."  Test the raw string rather than .fragment, which is "" both for
    # a URI with no fragment and for one ending in a bare "#" -- the latter is a
    # (empty) fragment component and is not the registered URI.  A percent-encoded
    # %23 is not a fragment delimiter and is unaffected.
    if "#" in uri:
        return False, [(None, "the requested URI has a fragment, which RFC 6749 section 3.1.2 forbids")]

    # Credentials are not part of a registered callback and must not ride along on
    # the request; without this "https://evil@example.com/cb" would match a
    # registered "https://example.com/cb", since only .hostname is compared below.
    if "@" in parsed_uri.netloc:
        return False, [(None, "the requested URI carries userinfo credentials in its authority")]

    for allowed_uri in allowed_uris:
        # A registered URI carrying a fragment or credentials cannot authorize
        # anything: the request forms that would match it are rejected above.
        if "#" in allowed_uri:
            reasons.append((allowed_uri, "the registered URI has a fragment and can never match"))
            continue

        parsed_allowed_uri = urlsplit(allowed_uri)

        if "@" in parsed_allowed_uri.netloc:
            reasons.append(
                (allowed_uri, "the registered URI carries userinfo credentials and can never match")
            )
            continue

        if parsed_allowed_uri.scheme != parsed_uri.scheme:
            # match failed, continue
            reasons.append((allowed_uri, "scheme differs"))
            continue

        """ check hostname """
        # A private-use URI scheme redirect (RFC 8252 §7.1) has no naming
        # authority, so hostname is None on either side; guard before matching.
        allowed_hostname = parsed_allowed_uri.hostname
        uri_hostname = parsed_uri.hostname
        if oauth2_settings.ALLOW_URI_WILDCARDS and allowed_hostname and allowed_hostname.startswith("*"):
            """ wildcard hostname """
            if not uri_hostname or not uri_hostname.endswith(allowed_hostname[1:]):
                reasons.append((allowed_uri, "hostname does not match the registered wildcard"))
                continue
        elif allowed_hostname != uri_hostname:
            reasons.append((allowed_uri, "hostname differs"))
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
        #
        # Section 8.3 notes that "localhost" redirect URIs "function similarly
        # to loopback IP redirects" but their use is NOT RECOMMENDED, so the
        # port exemption is not extended to the "localhost" hostname by
        # default.  Some native clients nonetheless register "localhost" and
        # receive the callback on an ephemeral port; ALLOW_LOCALHOST_LOOPBACK
        # opts in to treating it as loopback.  The hostname must still match
        # exactly, so "localhost" is never conflated with the IP literals.
        allowed_uri_is_loopback = parsed_allowed_uri.scheme == "http" and (
            parsed_allowed_uri.hostname in ("127.0.0.1", "::1")
            or (oauth2_settings.ALLOW_LOCALHOST_LOOPBACK and parsed_allowed_uri.hostname == "localhost")
        )
        """ check port """
        if not allowed_uri_is_loopback and parsed_allowed_uri.port != parsed_uri.port:
            reasons.append((allowed_uri, "port differs"))
            continue

        """ check path """
        if parsed_allowed_uri.path != parsed_uri.path:
            reasons.append((allowed_uri, "path differs"))
            continue

        """ check querystring """
        # RFC 9700 section 2.1 requires exact matching of the redirect URI (see
        # also OpenID Connect Core section 3.1.2.1, which mandates RFC 3986
        # section 6.2.1 Simple String Comparison).  This previously tested that
        # the registered query was a *subset* of the requested one, which let a
        # request carry query parameters that were never registered: an attacker
        # could append parameters to an otherwise-legitimate redirect URI and
        # have the authorization server reflect them into the client's callback
        # alongside the authorization code (RFC 9700 section 4.1).
        #
        # .query is "" both when there is no query component and when there is an
        # empty one ("https://example.com/cb?"), which are different URIs under
        # simple string comparison, so the delimiter's presence is compared too.
        # A "?" cannot appear in a scheme, authority or path -- the first one always
        # opens the query -- so testing the raw string is equivalent to testing for
        # the component.  A percent-encoded %3F is not a delimiter and is unaffected.
        if ("?" in allowed_uri) != ("?" in uri):
            reasons.append((allowed_uri, "one URI has a query component and the other does not"))
            continue
        if parsed_allowed_uri.query != parsed_uri.query:
            reasons.append((allowed_uri, "query string differs"))
            continue  # circuit break

        return True, []

    # if uris matched then it's not allowed
    return False, reasons


def redirect_to_uri_allowed(uri: str, allowed_uris: list[str]) -> bool:
    """
    Checks if a given uri can be redirected to based on the provided allowed_uris configuration.

    On top of exact matches, this function also handles loopback IPs based on RFC 8252.

    :param uri: URI to check
    :param allowed_uris: A list of URIs that are allowed
    """
    allowed, _reasons = check_redirect_to_uri_allowed(uri, allowed_uris)
    return allowed


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
