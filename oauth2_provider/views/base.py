import hashlib
import json
import logging
from urllib.parse import parse_qsl, urlencode, urlparse

from django import http
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import resolve_url
from django.urls.exceptions import NoReverseMatch
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, View
from oauthlib.oauth2.rfc8628 import errors as rfc8628_errors

from ..compat import login_not_required
from ..exceptions import OAuthToolkitError
from ..forms import AllowForm
from ..http import OAuth2ResponseRedirect
from ..models import (
    get_access_token_model,
    get_application_model,
    get_device_grant_model,
    get_or_create_oauth2_session,
)
from ..scopes import get_scopes_backend
from ..settings import oauth2_settings
from ..signals import app_authorized
from .mixins import OAuthLibMixin


log = logging.getLogger("oauth2_provider")


# login_not_required decorator to bypass LoginRequiredMiddleware
@method_decorator(login_not_required, name="dispatch")
class BaseAuthorizationView(LoginRequiredMixin, OAuthLibMixin, View):
    """
    Implements a generic endpoint to handle *Authorization Requests* as in :rfc:`4.1.1`. The view
    does not implement any strategy to determine *authorize/do not authorize* logic.
    The endpoint is used in the following flows:

    * Authorization code
    * Implicit grant

    """

    def dispatch(self, request, *args, **kwargs):
        self.oauth2_data = {}
        return super().dispatch(request, *args, **kwargs)

    def error_response(self, error, application, **kwargs):
        """
        Handle errors either by redirecting to redirect_uri with a json in the body containing
        error details or providing an error response
        """
        redirect, error_response = super().error_response(error, **kwargs)

        if redirect:
            return self.redirect(error_response["url"], application)

        status = error_response["error"].status_code
        return self.render_to_response(error_response, status=status)

    def create_authorization_response(self, request, scopes, credentials, allow):
        """
        Attach the OP authentication session to the authorization so the
        artifacts issued for it (grant, tokens, ID token) can be tied to the
        user agent's session. The session is minted lazily on the first
        authorization after login and reused afterwards.
        """
        session = get_or_create_oauth2_session(request)
        if session is not None:
            credentials = {**credentials, "oauth2_session_sid": str(session.sid)}
        return super().create_authorization_response(request, scopes, credentials, allow)

    def redirect(self, redirect_to, application):
        if application is None:
            # The application can be None in case of an error during app validation
            # In such cases, fall back to default ALLOWED_REDIRECT_URI_SCHEMES
            allowed_schemes = oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES
        else:
            allowed_schemes = application.get_allowed_schemes()
        return OAuth2ResponseRedirect(redirect_to, allowed_schemes)


RFC3339 = "%Y-%m-%dT%H:%M:%SZ"


class AuthorizationView(BaseAuthorizationView, FormView):
    """
    Implements an endpoint to handle *Authorization Requests* as in :rfc:`4.1.1` and prompting the
    user with a form to determine if she authorizes the client application to access her data.
    This endpoint is reached two times during the authorization process:
    * first receive a ``GET`` request from user asking authorization for a certain client
    application, a form is served possibly showing some useful info and prompting for
    *authorize/do not authorize*.

    * then receive a ``POST`` request possibly after user authorized the access

    Some information contained in the ``GET`` request and needed to create a Grant token during
    the ``POST`` request would be lost between the two steps above, so they are temporarily stored in
    hidden fields on the form.
    A possible alternative could be keeping such information in the session.

    The endpoint is used in the following flows:
    * Authorization code
    * Implicit grant
    """

    template_name = "oauth2_provider/authorize.html"
    form_class = AllowForm

    skip_authorization_completely = False

    def get_initial(self):
        # TODO: move this scopes conversion from and to string into a utils function
        scopes = self.oauth2_data.get("scope", self.oauth2_data.get("scopes", []))
        initial_data = {
            "redirect_uri": self.oauth2_data.get("redirect_uri", None),
            "scope": " ".join(scopes),
            "nonce": self.oauth2_data.get("nonce", None),
            "client_id": self.oauth2_data.get("client_id", None),
            "state": self.oauth2_data.get("state", None),
            "response_type": self.oauth2_data.get("response_type", None),
            "code_challenge": self.oauth2_data.get("code_challenge", None),
            "code_challenge_method": self.oauth2_data.get("code_challenge_method", None),
            "claims": self.oauth2_data.get("claims", None),
        }
        return initial_data

    def form_valid(self, form):
        client_id = form.cleaned_data["client_id"]
        application = get_application_model().objects.get(client_id=client_id)
        credentials = {
            "client_id": form.cleaned_data.get("client_id"),
            "redirect_uri": form.cleaned_data.get("redirect_uri"),
            "response_type": form.cleaned_data.get("response_type", None),
            "state": form.cleaned_data.get("state", None),
        }
        if form.cleaned_data.get("code_challenge", False):
            credentials["code_challenge"] = form.cleaned_data.get("code_challenge")
        if form.cleaned_data.get("code_challenge_method", False):
            credentials["code_challenge_method"] = form.cleaned_data.get("code_challenge_method")
        if form.cleaned_data.get("nonce", False):
            credentials["nonce"] = form.cleaned_data.get("nonce")
        if form.cleaned_data.get("claims", False):
            credentials["claims"] = form.cleaned_data.get("claims")

        scopes = form.cleaned_data.get("scope")
        allow = form.cleaned_data.get("allow")

        try:
            uri, headers, body, status = self.create_authorization_response(
                request=self.request, scopes=scopes, credentials=credentials, allow=allow
            )
        except OAuthToolkitError as error:
            return self.error_response(error, application)

        self.success_url = uri
        log.debug("Success url for the request: {0}".format(self.success_url))
        return self.redirect(self.success_url, application)

    def get(self, request, *args, **kwargs):
        try:
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolkitError as error:
            # Application is not available at this time.
            return self.error_response(error, application=None)

        # prompt is a space-delimited, case-sensitive list of ASCII values
        # (OpenID Connect Core 1.0 section 3.1.2.1). Prompt Create 1.0
        # recommends that create not be combined with other values, but when
        # it is, account creation has to happen before any of the others can
        # be satisfied, so create is handled first.
        prompt = set(request.GET.get("prompt", "").split())
        if "create" in prompt:
            # None means create is a no-op for this request (the user already
            # has an authenticated session): continue with the other prompt
            # values and the normal flow.
            response = self.handle_prompt_create()
            if response is not None:
                return response
        if "login" in prompt:
            return self.handle_prompt_login()

        all_scopes = get_scopes_backend().get_all_scopes()
        kwargs["scopes_descriptions"] = [all_scopes[scope] for scope in scopes]
        kwargs["scopes"] = scopes
        # at this point we know an Application instance with such client_id exists in the database

        # TODO: Cache this!
        application = get_application_model().objects.get(client_id=credentials["client_id"])

        kwargs["application"] = application
        kwargs["client_id"] = credentials["client_id"]
        kwargs["redirect_uri"] = credentials["redirect_uri"]
        kwargs["response_type"] = credentials["response_type"]
        kwargs["state"] = credentials["state"]
        if "code_challenge" in credentials:
            kwargs["code_challenge"] = credentials["code_challenge"]
        if "code_challenge_method" in credentials:
            kwargs["code_challenge_method"] = credentials["code_challenge_method"]
        if "nonce" in credentials:
            kwargs["nonce"] = credentials["nonce"]
        if "claims" in credentials:
            kwargs["claims"] = json.dumps(credentials["claims"])

        self.oauth2_data = kwargs
        # following two loc are here only because of https://code.djangoproject.com/ticket/17795
        form = self.get_form(self.get_form_class())
        kwargs["form"] = form

        # Check to see if the user has already granted access and return
        # a successful response depending on "approval_prompt" url parameter
        require_approval = request.GET.get("approval_prompt", oauth2_settings.REQUEST_APPROVAL_PROMPT)

        if "ui_locales" in credentials and isinstance(credentials["ui_locales"], list):
            # Make sure ui_locales a space separated string for oauthlib to handle it correctly.
            credentials["ui_locales"] = " ".join(credentials["ui_locales"])

        try:
            # If skip_authorization field is True, skip the authorization screen even
            # if this is the first use of the application and there was no previous authorization.
            # This is useful for in-house applications-> assume an in-house applications
            # are already approved.
            if application.skip_authorization:
                uri, headers, body, status = self.create_authorization_response(
                    request=self.request, scopes=" ".join(scopes), credentials=credentials, allow=True
                )
                return self.redirect(uri, application)

            elif require_approval == "auto":
                tokens = (
                    get_access_token_model()
                    .objects.filter(
                        user=request.user, application=kwargs["application"], expires__gt=timezone.now()
                    )
                    .all()
                )

                # check past authorizations regarded the same scopes as the current one
                for token in tokens:
                    if token.allow_scopes(scopes):
                        uri, headers, body, status = self.create_authorization_response(
                            request=self.request,
                            scopes=" ".join(scopes),
                            credentials=credentials,
                            allow=True,
                        )
                        return self.redirect(uri, application)

        except OAuthToolkitError as error:
            return self.error_response(error, application)

        return self.render_to_response(self.get_context_data(**kwargs))

    def handle_prompt_login(self):
        path = self.request.build_absolute_uri()
        resolved_login_url = resolve_url(self.get_login_url())

        # If the login url is the same scheme and net location then use the
        # path as the "next" url.
        login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
        current_scheme, current_netloc = urlparse(path)[:2]
        if (not login_scheme or login_scheme == current_scheme) and (
            not login_netloc or login_netloc == current_netloc
        ):
            path = self.request.get_full_path()

        parsed = urlparse(path)

        parsed_query = dict(parse_qsl(parsed.query))
        parsed_query.pop("prompt")

        parsed = parsed._replace(query=urlencode(parsed_query))

        return redirect_to_login(
            parsed.geturl(),
            resolved_login_url,
            self.get_redirect_field_name(),
        )

    def handle_prompt_create(self):
        """
        When the prompt parameter of the authorization request contains
        create, redirect unauthenticated users to the registration page.
        After registration, the user should be redirected back to the
        authorization endpoint, with create removed from the prompt
        parameter, to continue the OIDC flow.

        For a user with an existing authenticated session, create is a
        no-op: None is returned and the authorization request proceeds as
        if create was not present. The spec leaves this case open ("whether
        the AS creates a brand new identity or helps the user authenticate
        an identity they already have is out of scope") and this matches
        how major providers treat a signup hint alongside an active
        session. A Relying Party that wants re-authentication instead can
        combine prompt values, e.g. "create login".

        Implements OpenID Connect Prompt Create 1.0 specification.
        https://openid.net/specs/openid-connect-prompt-create-1_0.html
        """
        # Per Prompt Create 1.0 section 4.1.1, an OP receiving a prompt value it
        # does not support (one not declared in prompt_values_supported) SHOULD
        # respond with HTTP 400 and an error value of invalid_request.
        if not oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_ENABLED:
            return JsonResponse(
                {"error": "invalid_request", "error_description": "prompt=create is not supported"},
                status=400,
            )

        # The no-op for authenticated sessions comes before the registration
        # URL is resolved: these requests never redirect to registration, so
        # a misconfigured URL must not break them. Anonymous create requests
        # below still surface the misconfiguration loudly.
        if self.request.user.is_authenticated:
            return None

        # An enabled feature without a resolvable registration page is server
        # misconfiguration, not a client error: fail loudly for the operator
        # instead of sending a misleading error to the relying party.
        registration_location = oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_URL
        if not registration_location:
            raise ImproperlyConfigured(
                "OIDC_RP_INITIATED_REGISTRATION_URL must be set when "
                "OIDC_RP_INITIATED_REGISTRATION_ENABLED is True."
            )
        try:
            # Like LOGIN_URL, accepts a URL pattern name, a path or an absolute URL.
            registration_url = resolve_url(registration_location)
        except NoReverseMatch as exc:
            raise ImproperlyConfigured(
                f"OIDC_RP_INITIATED_REGISTRATION_URL {registration_location!r} could not be "
                "resolved to a registration page."
            ) from exc

        # The request MUST be validated against a registered client before
        # the user is redirected anywhere: an invalid request has to fail here
        # (safely — when entered via handle_no_permission no validation has
        # run yet, and error_response never redirects to an unregistered
        # redirect_uri) rather than after the user has created an account.
        try:
            self.validate_authorization_request(self.request)
        except OAuthToolkitError as error:
            return self.error_response(error, application=None)

        # Build the next parameter so the user returns to the authorization
        # endpoint after registration. Drop create from the prompt parameter
        # so the flow continues, but keep any other prompt values the RP sent
        # (e.g. "login create").
        parsed = urlparse(self.request.build_absolute_uri())
        parsed_query = dict(parse_qsl(parsed.query))
        other_prompts = [p for p in parsed_query.pop("prompt", "").split() if p != "create"]
        if other_prompts:
            parsed_query["prompt"] = " ".join(other_prompts)
        next_url = parsed._replace(query=urlencode(parsed_query)).geturl()

        # Merge next into the registration URL's query so an existing query
        # string or fragment in the configured URL is preserved.
        parsed_registration = urlparse(registration_url)
        registration_query = dict(parse_qsl(parsed_registration.query))
        registration_query["next"] = next_url
        redirect_to = parsed_registration._replace(query=urlencode(registration_query)).geturl()
        return HttpResponseRedirect(redirect_to)

    def handle_no_permission(self):
        """
        Generate response for unauthorized users.

        If the prompt parameter contains none, then we redirect with an error
        code as defined by OpenID Connect Core 1.0 section 3.1.2.6
        (Authentication Error Response)
        <https://openid.net/specs/openid-connect-core-1_0.html#AuthError>.

        If the prompt parameter contains create, then we redirect to the
        registration page.

        If the prompt parameter contains login, then we redirect straight to
        the login flow with the prompt consumed, so the user is not sent to
        login a second time when they return to this endpoint authenticated.

        Some code copied from OAuthLibMixin.error_response, but that is designed
        to operate on OAuth2Error from oauthlib wrapped in a OAuthToolkitError
        """
        # prompt is a space-delimited, case-sensitive list of ASCII values
        # (OpenID Connect Core 1.0 section 3.1.2.1).
        prompt = set(self.request.GET.get("prompt", "").split())
        if "none" in prompt:
            # Per OpenID Connect Core 1.0 section 3.1.2.6 (Authentication Error
            # Response) an unauthenticated prompt=none request returns a
            # login_required error to the client's redirect_uri. The request
            # MUST be validated against a registered client *before* redirecting,
            # otherwise this endpoint becomes an open redirector: an
            # unauthenticated attacker could supply an arbitrary, unregistered
            # redirect_uri (and no client_id) and have the victim's browser 302'd
            # to an attacker-controlled origin.
            # https://openid.net/specs/openid-connect-core-1_0.html#AuthError
            # none combined with any other value is itself invalid (Core
            # section 3.1.2.1); oauthlib rejects the combination during
            # validation, so it errors here instead of falling through to an
            # interactive redirect.
            try:
                _scopes, credentials = self.validate_authorization_request(self.request)
            except OAuthToolkitError as error:
                # Invalid client_id / redirect_uri (etc). error_response only
                # redirects for non-fatal errors, and never to an unregistered
                # redirect_uri, so this is safe.
                return self.error_response(error, application=None)

            # oauthlib has confirmed redirect_uri is registered for the client.
            redirect_uri = credentials["redirect_uri"]
            application = get_application_model().objects.get(client_id=credentials["client_id"])

            response_parameters = {"error": "login_required"}

            # REQUIRED if the Authorization Request included the state parameter.
            # Set to the value received from the Client
            state = credentials.get("state")
            if state:
                response_parameters["state"] = state

            separator = "&" if "?" in redirect_uri else "?"
            redirect_to = redirect_uri + separator + urlencode(response_parameters)
            return self.redirect(redirect_to, application)

        if "create" in prompt:
            # If prompt contains create and the user is not authenticated,
            # redirect to registration.
            return self.handle_prompt_create()

        if "login" in prompt:
            # Logging in satisfies the login prompt, and handle_prompt_login
            # strips it from the next URL. Falling through to the default
            # redirect instead would keep prompt=login in next, bouncing the
            # user to the login page a second time after they authenticate.
            return self.handle_prompt_login()

        return super().handle_no_permission()


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class TokenView(OAuthLibMixin, View):
    """
    Implements an endpoint to provide access tokens

    The endpoint is used in the following flows:
    * Authorization code
    * Password
    * Client credentials
    * Device code flow (specifically for the device polling stage)
    """

    @method_decorator(sensitive_post_parameters("password", "client_secret"))
    def authorization_flow_token_response(
        self, request: http.HttpRequest, *args, **kwargs
    ) -> http.HttpResponse:
        url, headers, body, status = self.create_token_response(request)
        if status == 200:
            access_token = json.loads(body).get("access_token")
            if access_token is not None:
                token_checksum = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
                token = get_access_token_model().objects.get(token_checksum=token_checksum)
                app_authorized.send(sender=self, request=request, token=token)
        response = HttpResponse(content=body, status=status)

        for k, v in headers.items():
            response[k] = v
        return response

    def device_flow_token_response(
        self, request: http.HttpRequest, device_code: str, *args, **kwargs
    ) -> http.HttpResponse:
        device_grant_model = get_device_grant_model()
        try:
            device = device_grant_model.objects.get(device_code=device_code)
        except device_grant_model.DoesNotExist:
            # The RFC does not mention what to return when the device is not found,
            # but to keep it consistent with the other errors, we return the error
            # in json format with an "error" key and the value formatted in the same
            # way.
            return http.HttpResponseNotFound(
                content='{"error": "device_not_found"}',
                content_type="application/json",
            )

        # Here we are returning the errors according to
        # https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
        # TODO: "slow_down" error (essentially rate-limiting).
        if device.status == device.AUTHORIZATION_PENDING:
            error = rfc8628_errors.AuthorizationPendingError()
        elif device.status == device.DENIED:
            error = rfc8628_errors.AccessDenied()
        elif device.status == device.EXPIRED:
            error = rfc8628_errors.ExpiredTokenError()
        elif device.status != device.AUTHORIZED:
            # It's technically impossible to get here because we've exhausted
            # all the possible values for status. However, it does act as a
            # reminder for developers when they add, in the future, new values
            # (such as slow_down) that they must handle here.
            return http.HttpResponseServerError(
                content='{"error": "internal_error"}',
                content_type="application/json",
            )
        else:
            # AUTHORIZED is the only accepted state, anything else is
            # rejected.
            error = None

        if error:
            return http.HttpResponse(
                content=error.json,
                status=error.status_code,
                content_type="application/json",
            )

        url, headers, body, status = self.create_token_response(request)
        response = http.JsonResponse(data=json.loads(body), status=status)

        if status != 200:
            return response

        for k, v in headers.items():
            response[k] = v

        return response

    def post(self, request: http.HttpRequest, *args, **kwargs) -> http.HttpResponse:
        params = request.POST
        if params.get("grant_type") == "urn:ietf:params:oauth:grant-type:device_code":
            return self.device_flow_token_response(request, params["device_code"])
        return self.authorization_flow_token_response(request)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class RevokeTokenView(OAuthLibMixin, View):
    """
    Implements an endpoint to revoke access or refresh tokens
    """

    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_revocation_response(request)
        response = HttpResponse(content=body or "", status=status)

        for k, v in headers.items():
            response[k] = v
        return response
