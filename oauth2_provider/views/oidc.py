import json
from urllib.parse import urlparse

from django.contrib.auth import logout
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import FormView, View
from jwcrypto import jwt
from jwcrypto.common import JWException
from jwcrypto.jws import InvalidJWSObject
from jwcrypto.jwt import JWTExpired
from oauthlib.common import add_params_to_uri

from ..compat import login_not_required
from ..exceptions import (
    ClientIdMissmatch,
    InvalidIDTokenError,
    InvalidOIDCClientError,
    InvalidOIDCRedirectURIError,
    LogoutDenied,
    OIDCError,
)
from ..forms import ConfirmLogoutForm
from ..http import OAuth2ResponseRedirect
from ..models import (
    AbstractGrant,
    get_access_token_model,
    get_application_model,
    get_id_token_model,
    get_refresh_token_model,
)
from ..settings import oauth2_settings
from ..utils import jwk_from_pem
from .mixins import OAuthLibMixin, OIDCLogoutOnlyMixin, OIDCOnlyMixin


Application = get_application_model()


@method_decorator(login_not_required, name="dispatch")
class ConnectDiscoveryInfoView(OIDCOnlyMixin, View):
    """
    View used to show oidc provider configuration information per
    `OpenID Provider Metadata <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>`_
    """

    def get(self, request, *args, **kwargs):
        issuer_url = oauth2_settings.OIDC_ISS_ENDPOINT

        if not issuer_url:
            issuer_url = oauth2_settings.oidc_issuer(request)
            authorization_endpoint = request.build_absolute_uri(reverse("oauth2_provider:authorize"))
            token_endpoint = request.build_absolute_uri(reverse("oauth2_provider:token"))
            userinfo_endpoint = oauth2_settings.OIDC_USERINFO_ENDPOINT or request.build_absolute_uri(
                reverse("oauth2_provider:user-info")
            )
            jwks_uri = request.build_absolute_uri(reverse("oauth2_provider:jwks-info"))
            if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED:
                end_session_endpoint = request.build_absolute_uri(
                    reverse("oauth2_provider:rp-initiated-logout")
                )
        else:
            parsed_url = urlparse(oauth2_settings.OIDC_ISS_ENDPOINT)
            host = parsed_url.scheme + "://" + parsed_url.netloc
            authorization_endpoint = "{}{}".format(host, reverse("oauth2_provider:authorize"))
            token_endpoint = "{}{}".format(host, reverse("oauth2_provider:token"))
            userinfo_endpoint = oauth2_settings.OIDC_USERINFO_ENDPOINT or "{}{}".format(
                host, reverse("oauth2_provider:user-info")
            )
            jwks_uri = "{}{}".format(host, reverse("oauth2_provider:jwks-info"))
            if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED:
                end_session_endpoint = "{}{}".format(host, reverse("oauth2_provider:rp-initiated-logout"))

        signing_algorithms = [Application.HS256_ALGORITHM]
        if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            signing_algorithms = [Application.RS256_ALGORITHM, Application.HS256_ALGORITHM]

        validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
        validator = validator_class()
        oidc_claims = list(set(validator.get_discovery_claims(request)))
        scopes_class = oauth2_settings.SCOPES_BACKEND_CLASS
        scopes = scopes_class()
        scopes_supported = [scope for scope in scopes.get_available_scopes()]

        data = {
            "issuer": issuer_url,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "userinfo_endpoint": userinfo_endpoint,
            "jwks_uri": jwks_uri,
            "scopes_supported": scopes_supported,
            "response_types_supported": oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED,
            "subject_types_supported": oauth2_settings.OIDC_SUBJECT_TYPES_SUPPORTED,
            "id_token_signing_alg_values_supported": signing_algorithms,
            "token_endpoint_auth_methods_supported": (
                oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED
            ),
            "code_challenge_methods_supported": [key for key, _ in AbstractGrant.CODE_CHALLENGE_METHODS],
            "claims_supported": oidc_claims,
        }
        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ENABLED:
            data["end_session_endpoint"] = end_session_endpoint
        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


@method_decorator(login_not_required, name="dispatch")
class JwksInfoView(OIDCOnlyMixin, View):
    """
    View used to show oidc json web key set document
    """

    def get(self, request, *args, **kwargs):
        keys = []
        if oauth2_settings.OIDC_RSA_PRIVATE_KEY:
            for pem in [
                oauth2_settings.OIDC_RSA_PRIVATE_KEY,
                *oauth2_settings.OIDC_RSA_PRIVATE_KEYS_INACTIVE,
            ]:
                key = jwk_from_pem(pem)
                data = {"alg": "RS256", "use": "sig", "kid": key.thumbprint()}
                data.update(json.loads(key.export_public()))
                keys.append(data)
        response = JsonResponse({"keys": keys})
        response["Access-Control-Allow-Origin"] = "*"
        response["Cache-Control"] = (
            "Cache-Control: public, "
            + f"max-age={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}, "
            + f"stale-while-revalidate={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}, "
            + f"stale-if-error={oauth2_settings.OIDC_JWKS_MAX_AGE_SECONDS}"
        )
        return response


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class UserInfoView(OIDCOnlyMixin, OAuthLibMixin, View):
    """
    View used to show Claims about the authenticated End-User
    """

    def get(self, request, *args, **kwargs):
        return self._create_userinfo_response(request)

    def post(self, request, *args, **kwargs):
        return self._create_userinfo_response(request)

    def _create_userinfo_response(self, request):
        url, headers, body, status = self.create_userinfo_response(request)
        response = HttpResponse(content=body or "", status=status)

        for k, v in headers.items():
            response[k] = v
        return response


def _load_id_token(token):
    """
    Loads an IDToken given its string representation for use with RP-Initiated Logout.
    A tuple (IDToken, claims) is returned. Depending on the configuration expired tokens may be loaded.
    If loading failed (None, None) is returned.
    """
    IDToken = get_id_token_model()
    validator = oauth2_settings.OAUTH2_VALIDATOR_CLASS()

    try:
        key = validator._get_key_for_token(token)
    except InvalidJWSObject:
        # Failed to deserialize the key.
        return None, None

    # Could not identify key from the ID Token.
    if not key:
        return None, None

    try:
        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ACCEPT_EXPIRED_TOKENS:
            # Only check the following while loading the JWT
            # - claims are dict
            # - the Claims defined in RFC7519 if present have the correct type (string, integer, etc.)
            # The claim contents are not validated. `exp` and `nbf` in particular are not validated.
            check_claims = {}
        else:
            # Also validate the `exp` (expiration time) and `nbf` (not before) claims.
            check_claims = None
        jwt_token = jwt.JWT(key=key, jwt=token, check_claims=check_claims)
        claims = json.loads(jwt_token.claims)

        # Assumption: the `sub` claim and `user` property of the corresponding IDToken Object point to the
        # same user.
        # To verify that the IDToken was intended for the user it is therefore sufficient to check the `user`
        # attribute on the IDToken Object later on.

        return IDToken.objects.get(jti=claims["jti"]), claims

    except (JWException, JWTExpired, IDToken.DoesNotExist):
        return None, None


def _validate_claims(request, claims):
    """
    Validates the claims of an IDToken for use with OIDC RP-Initiated Logout.
    """
    validator = oauth2_settings.OAUTH2_VALIDATOR_CLASS()

    # Verification of `iss` claim is mandated by OIDC RP-Initiated Logout specs.
    if "iss" not in claims or claims["iss"] != validator.get_oidc_issuer_endpoint(request):
        # IDToken was not issued by this OP, or it can not be verified.
        return False

    return True


@method_decorator(login_not_required, name="dispatch")
class RPInitiatedLogoutView(OIDCLogoutOnlyMixin, FormView):
    template_name = "oauth2_provider/logout_confirm.html"
    form_class = ConfirmLogoutForm
    # Only delete tokens for Application whose client type and authorization
    # grant type are in the respective lists.
    token_deletion_client_types = [
        Application.CLIENT_PUBLIC,
        Application.CLIENT_CONFIDENTIAL,
    ]
    token_deletion_grant_types = [
        Application.GRANT_AUTHORIZATION_CODE,
        Application.GRANT_IMPLICIT,
        Application.GRANT_PASSWORD,
        Application.GRANT_CLIENT_CREDENTIALS,
        Application.GRANT_OPENID_HYBRID,
    ]

    def get_initial(self):
        return {
            "id_token_hint": self.oidc_data.get("id_token_hint", None),
            "logout_hint": self.oidc_data.get("logout_hint", None),
            "client_id": self.oidc_data.get("client_id", None),
            "post_logout_redirect_uri": self.oidc_data.get("post_logout_redirect_uri", None),
            "state": self.oidc_data.get("state", None),
            "ui_locales": self.oidc_data.get("ui_locales", None),
        }

    def dispatch(self, request, *args, **kwargs):
        self.oidc_data = {}
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        id_token_hint = request.GET.get("id_token_hint")
        client_id = request.GET.get("client_id")
        post_logout_redirect_uri = request.GET.get("post_logout_redirect_uri")
        state = request.GET.get("state")

        try:
            application, token_user = self.validate_logout_request(
                id_token_hint=id_token_hint,
                client_id=client_id,
                post_logout_redirect_uri=post_logout_redirect_uri,
            )
        except OIDCError as error:
            return self.error_response(error)

        if not self.must_prompt(token_user):
            return self.do_logout(application, post_logout_redirect_uri, state, token_user)

        self.oidc_data = {
            "id_token_hint": id_token_hint,
            "client_id": client_id,
            "post_logout_redirect_uri": post_logout_redirect_uri,
            "state": state,
        }
        form = self.get_form(self.get_form_class())
        kwargs["form"] = form
        if application:
            kwargs["application"] = application

        return self.render_to_response(self.get_context_data(**kwargs))

    def form_valid(self, form):
        id_token_hint = form.cleaned_data.get("id_token_hint")
        client_id = form.cleaned_data.get("client_id")
        post_logout_redirect_uri = form.cleaned_data.get("post_logout_redirect_uri")
        state = form.cleaned_data.get("state")

        try:
            application, token_user = self.validate_logout_request(
                id_token_hint=id_token_hint,
                client_id=client_id,
                post_logout_redirect_uri=post_logout_redirect_uri,
            )

            if not self.must_prompt(token_user) or form.cleaned_data.get("allow"):
                return self.do_logout(application, post_logout_redirect_uri, state, token_user)
            else:
                raise LogoutDenied()

        except OIDCError as error:
            return self.error_response(error)

    def validate_post_logout_redirect_uri(self, application, post_logout_redirect_uri):
        """
        Validate the OIDC RP-Initiated Logout Request post_logout_redirect_uri parameter
        """

        if not post_logout_redirect_uri:
            return

        if not application:
            raise InvalidOIDCClientError()
        scheme = urlparse(post_logout_redirect_uri)[0]
        if not scheme:
            raise InvalidOIDCRedirectURIError("A Scheme is required for the redirect URI.")
        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_STRICT_REDIRECT_URIS and (
            scheme == "http" and application.client_type != "confidential"
        ):
            raise InvalidOIDCRedirectURIError("http is only allowed with confidential clients.")
        if scheme not in application.get_allowed_schemes():
            raise InvalidOIDCRedirectURIError(f'Redirect to scheme "{scheme}" is not permitted.')
        if not application.post_logout_redirect_uri_allowed(post_logout_redirect_uri):
            raise InvalidOIDCRedirectURIError("This client does not have this redirect uri registered.")

    def validate_logout_request_user(self, id_token_hint, client_id):
        """
        Validate the an OIDC RP-Initiated Logout Request user
        """

        if not id_token_hint:
            return

        # Only basic validation has been done on the IDToken at this point.
        id_token, claims = _load_id_token(id_token_hint)

        if not id_token or not _validate_claims(self.request, claims):
            raise InvalidIDTokenError()

        # If both id_token_hint and client_id are given it must be verified that they match.
        if client_id:
            if id_token.application.client_id != client_id:
                raise ClientIdMissmatch()

        return id_token

    def get_request_application(self, id_token, client_id):
        if client_id:
            return get_application_model().objects.get(client_id=client_id)
        if id_token:
            return id_token.application

    def validate_logout_request(self, id_token_hint, client_id, post_logout_redirect_uri):
        """
        Validate an OIDC RP-Initiated Logout Request.
        `(application, token_user)` is returned.

        If it is set, `application` is the Application that is requesting the logout.
        `token_user` is the id_token user, which will used to revoke the tokens if found.

        The `id_token_hint` will be validated if given. If both `client_id` and `id_token_hint` are given they
        will be validated against each other.
        """

        id_token = self.validate_logout_request_user(id_token_hint, client_id)
        application = self.get_request_application(id_token, client_id)
        self.validate_post_logout_redirect_uri(application, post_logout_redirect_uri)

        return application, id_token.user if id_token else None

    def must_prompt(self, token_user):
        """
        per: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

        > At the Logout Endpoint, the OP SHOULD ask the End-User whether to log
        > out of the OP as well. Furthermore, the OP MUST ask the End-User this
        > question if an id_token_hint was not provided or if the supplied ID
        > Token does not belong to the current OP session with the RP and/or
        > currently logged in End-User.

        """

        if not self.request.user.is_authenticated:
            """
            > the OP MUST ask ask the End-User whether to log out of the OP as

            If the user does not have an active session with the OP, they cannot
            end their OP session, so there is nothing to prompt for. This occurs
            in cases where the user has logged out of the OP via another channel
            such as the OP's own logout page, session timeout or another RP's
            logout page.
            """
            return False

        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT:
            """
            > At the Logout Endpoint, the OP SHOULD ask the End-User whether to
            > log out of the OP as well

            The admin has configured the OP to always prompt the userfor logout
            per the SHOULD recommendation.
            """
            return True

        if token_user is None:
            """
            > the OP MUST ask ask the End-User whether to log out of the OP as
            > well if the supplied ID Token does not belong to the current OP
            > session with the RP.

            token_user will only be populated if an ID token was found for the
            RP (Application) that is requesting the logout. If token_user is not
            then we must prompt the user.
            """
            return True

        if token_user != self.request.user:
            """
            > the OP MUST ask ask the End-User whether to log out of the OP as
            > well if the supplied ID Token does not belong to the logged in
            > End-User.

            is_authenticated indicates that there is a logged in user and was
            tested in the first condition.
            token_user != self.request.user indicates that the token does not
            belong to the logged in user, Therefore we need to prompt the user.
            """
            return True

        """ We didn't find a reason to prompt the user """
        return False

    def do_logout(self, application=None, post_logout_redirect_uri=None, state=None, token_user=None):
        user = token_user or self.request.user
        # Delete Access Tokens if a user was found
        if oauth2_settings.OIDC_RP_INITIATED_LOGOUT_DELETE_TOKENS and not isinstance(user, AnonymousUser):
            AccessToken = get_access_token_model()
            RefreshToken = get_refresh_token_model()
            access_tokens_to_delete = AccessToken.objects.filter(
                user=user,
                application__client_type__in=self.token_deletion_client_types,
                application__authorization_grant_type__in=self.token_deletion_grant_types,
            )
            # This queryset has to be evaluated eagerly. The queryset would be empty with lazy evaluation
            # because `access_tokens_to_delete` represents an empty queryset once `refresh_tokens_to_delete`
            # is evaluated as all AccessTokens have been deleted.
            refresh_tokens_to_delete = list(
                RefreshToken.objects.filter(access_token__in=access_tokens_to_delete)
            )
            for token in access_tokens_to_delete:
                # Delete the token and its corresponding refresh and IDTokens.
                if token.id_token:
                    token.id_token.revoke()
                token.revoke()
            for refresh_token in refresh_tokens_to_delete:
                refresh_token.revoke()
        # Logout in Django
        logout(self.request)
        # Redirect
        if post_logout_redirect_uri:
            if state:
                return OAuth2ResponseRedirect(
                    add_params_to_uri(post_logout_redirect_uri, [("state", state)]),
                    application.get_allowed_schemes(),
                )
            else:
                return OAuth2ResponseRedirect(post_logout_redirect_uri, application.get_allowed_schemes())
        else:
            return OAuth2ResponseRedirect(
                self.request.build_absolute_uri("/"),
                oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES,
            )

    def error_response(self, error):
        error_response = {"error": error}
        return self.render_to_response(error_response, status=error.status_code)
