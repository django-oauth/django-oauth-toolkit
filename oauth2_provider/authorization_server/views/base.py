import hashlib
import json
import logging
from urllib.parse import parse_qsl, urlencode, urlparse

from django import http
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, QueryDict
from django.shortcuts import resolve_url
from django.urls.exceptions import NoReverseMatch
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import escape_uri_path
from django.views.decorators.csrf import csrf_exempt, csrf_protect, ensure_csrf_cookie
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, View
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error, OAuth2Error
from oauthlib.oauth2.rfc8628 import errors as rfc8628_errors
from oauthlib.openid.connect.core.exceptions import RequestNotSupported, RequestURINotSupported

from oauth2_provider.authorization_server import par
from oauth2_provider.authorization_server.forms import AllowForm
from oauth2_provider.authorization_server.response_modes import add_params_to_authorization_redirect
from oauth2_provider.authorization_server.views.mixins import AuthorizationServerViewMixin
from oauth2_provider.core.compat import login_not_required
from oauth2_provider.core.exceptions import FatalClientError, OAuthToolkitError
from oauth2_provider.core.http import OAuth2ResponseRedirect
from oauth2_provider.core.scopes import get_scopes_backend
from oauth2_provider.core.signals import app_authorized
from oauth2_provider.core.utils import add_iss_to_redirect
from oauth2_provider.core.views import FormEncodedRequestMixin
from oauth2_provider.models import get_access_token_model, get_application_model, get_device_grant_model
from oauth2_provider.resource_server.validators import is_valid_resource_uri
from oauth2_provider.settings import oauth2_settings


log = logging.getLogger("oauth2_provider")


# login_not_required decorator to bypass LoginRequiredMiddleware
@method_decorator(login_not_required, name="dispatch")
class BaseAuthorizationView(LoginRequiredMixin, AuthorizationServerViewMixin, View):
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

    def redirect(self, redirect_to, application):
        if application is None:
            # The application can be None in case of an error during app validation
            # In such cases, fall back to default ALLOWED_REDIRECT_URI_SCHEMES
            allowed_schemes = oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES
        else:
            allowed_schemes = application.get_allowed_schemes()
        return OAuth2ResponseRedirect(redirect_to, allowed_schemes)


RFC3339 = "%Y-%m-%dT%H:%M:%SZ"


@method_decorator(login_not_required, name="dispatch")
class AuthorizationView(BaseAuthorizationView, FormView):
    """
    Implements an endpoint to handle *Authorization Requests* as in :rfc:`4.1.1` and prompting the
    user with a form to determine if she authorizes the client application to access her data.
    This endpoint is reached two times during the authorization process:
    * first receive a ``GET`` request from user asking authorization for a certain client
    application, a form is served possibly showing some useful info and prompting for
    *authorize/do not authorize*.

    * then receive a ``POST`` request possibly after user authorized the access

    The authorization request itself may also be sent by ``POST``, with its parameters
    form-serialized in the body (OpenID Connect Core 1.0 section 3.1.2.1). Such a request
    is told apart from a consent submission by :meth:`is_consent_submission` and answered
    with a redirect to the same request sent by ``GET``.

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
            "response_mode": self.oauth2_data.get("response_mode", None),
            "code_challenge": self.oauth2_data.get("code_challenge", None),
            "code_challenge_method": self.oauth2_data.get("code_challenge_method", None),
            "claims": self.oauth2_data.get("claims", None),
            "resource": self.oauth2_data.get("resource", None),  # RFC 8707
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
        # A custom authorize.html may not render the response_mode field; the URL the
        # form posts back to still carries it, except after a pushed request.
        response_mode = form.cleaned_data.get("response_mode") or self.request.GET.get("response_mode")
        if response_mode:
            credentials["response_mode"] = response_mode
        if form.cleaned_data.get("code_challenge", False):
            credentials["code_challenge"] = form.cleaned_data.get("code_challenge")
        if form.cleaned_data.get("code_challenge_method", False):
            credentials["code_challenge_method"] = form.cleaned_data.get("code_challenge_method")
        if form.cleaned_data.get("nonce", False):
            credentials["nonce"] = form.cleaned_data.get("nonce")
        if form.cleaned_data.get("claims", False):
            credentials["claims"] = form.cleaned_data.get("claims")
        if form.cleaned_data.get("resource", False):  # RFC 8707
            resource_value = form.cleaned_data.get("resource")
            # RFC 8707 uses repeated query params for multiple resources, but the
            # authorization form stores them as a single whitespace-separated hidden field.
            # str.split() with no argument splits on any whitespace run and yields a
            # single-element list for one URI, so no special-casing is needed.
            resource_list = resource_value.split()
            # The GET handler validates these, but the hidden form field can be
            # tampered with; re-validate before anything is stored on the grant.
            for resource_uri in resource_list:
                if not is_valid_resource_uri(resource_uri):
                    error = OAuthToolkitError(
                        error=CustomOAuth2Error(
                            error="invalid_target",
                            description=(
                                f"The resource '{resource_uri}' is not a valid resource indicator: "
                                "it must be an absolute URI with a scheme and host."
                            ),
                            # RFC 6749: error redirects must echo the client's state
                            state=credentials.get("state"),
                        ),
                        redirect_uri=credentials["redirect_uri"],
                    )
                    # Lets error_response encode it like the successful response.
                    error.oauthlib_error.response_type = credentials["response_type"]
                    error.oauthlib_error.response_mode = credentials.get("response_mode")
                    return self.error_response(error, application)
            credentials["resource"] = resource_list

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

    def _fatal_par_error(self, description: str) -> http.HttpResponse:
        """Render a non-redirecting authorization error (RFC 9126).

        Used for request_uri and PAR-enforcement failures: there is no validated
        redirect_uri to trust, so the error is shown to the resource owner rather
        than redirected (which would risk an open redirect).
        """
        error = FatalClientError(error=CustomOAuth2Error(error="invalid_request", description=description))
        return self.error_response(error, application=None)

    def _resolve_pushed_request_uri(
        self, request: http.HttpRequest, request_uri: str
    ) -> http.HttpResponse | None:
        """Replace an incoming ``request_uri`` with the parameters pushed to the PAR
        endpoint (RFC 9126 §4), or return an error response.

        The consume/binding/expiry logic lives in :mod:`oauth2_provider.par`; here we
        only re-inject the resolved parameters into the request and render errors.
        """
        try:
            parameters = par.consume_pushed_request(request_uri, request.GET.get("client_id"))
        except par.PushedAuthorizationError as error:
            return self._fatal_par_error(error.description)
        # Re-inject the pushed parameters so the existing authorization flow, which
        # reads from the query string, proceeds unchanged. Any parameters supplied
        # alongside request_uri are intentionally ignored: the pushed request is
        # authoritative (RFC 9126), which prevents parameter injection.
        self._replace_query(request, parameters)
        return None

    @staticmethod
    def _replace_query(request: http.HttpRequest, parameters: dict) -> None:
        """Replace the request's query string, which the authorization flow reads from."""
        query_string = urlencode(parameters, doseq=True)
        request.GET = QueryDict(query_string, mutable=False)
        request.META["QUERY_STRING"] = query_string

    def _handle_pushed_authorization_request(self, request: http.HttpRequest) -> http.HttpResponse | None:
        """Resolve a pushed ``request_uri`` or enforce mandatory PAR (RFC 9126).

        Returns an error response to short-circuit the view, or ``None`` to continue
        with the (possibly rewritten) request.
        """
        request_uri = request.GET.get("request_uri")
        # Only PAR request URIs are resolved here; any other request_uri (OpenID
        # Connect Core 1.0 section 6.2) is rejected by _reject_request_objects.
        if request_uri and request_uri.startswith(par.REQUEST_URI_PREFIX):
            return self._resolve_pushed_request_uri(request, request_uri)
        if par.pushed_authorization_required(request.GET.get("client_id")):
            if oauth2_settings.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS:
                message = "This authorization server requires pushed authorization requests."
            else:
                message = "Pushed authorization requests are required for this client."
            return self._fatal_par_error(message)
        return None

    def _reject_request_objects(self, request: http.HttpRequest) -> http.HttpResponse | None:
        """Reject the ``request`` and non-PAR ``request_uri`` parameters.

        Request objects (OpenID Connect Core 1.0 section 6) are not supported, so
        such a request is answered with ``request_not_supported`` or
        ``request_uri_not_supported`` (section 3.1.2.6). The error is redirected
        only once the client and redirect URI have been validated; otherwise it is
        rendered like any other fatal authorization error.

        This runs from :meth:`dispatch`, before the login gate: the request is
        validated before the end-user is authenticated (sections 3.1.2.2 and
        3.1.2.3), so an anonymous request, including a ``prompt=none`` one, gets
        the unsupported-parameter error rather than a login page or
        ``login_required``.

        Returns ``None`` to leave the request to the normal flow: when it carries
        neither parameter, when its ``request_uri`` is a PAR request URI (the
        pushed request is authoritative, and the PAR endpoint refuses to store
        either parameter), and when the client must use PAR, which the PAR
        enforcement in :meth:`get` reports instead.
        """
        request_uri = request.GET.get("request_uri")
        if request_uri and request_uri.startswith(par.REQUEST_URI_PREFIX):
            return None
        if request.GET.get("request"):
            error_class = RequestNotSupported
        elif request_uri:
            error_class = RequestURINotSupported
        else:
            return None
        if par.pushed_authorization_required(request.GET.get("client_id")):
            return None

        # Validate what remains of the request so the error only goes to a
        # registered redirect URI, with the client's state echoed.
        self._replace_query(
            request,
            {key: values for key, values in request.GET.lists() if key not in ("request", "request_uri")},
        )
        try:
            _scopes, credentials = self.validate_authorization_request(request)
            client_id = credentials["client_id"]
            redirect_uri = credentials["redirect_uri"]
            state = credentials.get("state")
        except FatalClientError as error:
            return self.error_response(error, application=None)
        except OAuthToolkitError as error:
            # Any other error may be down to parameters that were only sent inside
            # the unsupported request object (a nonce, say), so report the
            # unsupported parameter rather than the symptom.
            oauthlib_error: OAuth2Error = error.oauthlib_error
            client_id = oauthlib_error.client_id
            redirect_uri = oauthlib_error.redirect_uri
            state = oauthlib_error.state

        unsupported = error_class(state=state)
        # Carry what oauthlib records from a request, so the error is encoded with
        # the response mode the client's response type calls for.
        unsupported.client_id = client_id
        unsupported.response_type = request.GET.get("response_type")
        unsupported.response_mode = request.GET.get("response_mode")
        if not redirect_uri:
            return self.error_response(FatalClientError(error=unsupported), application=None)
        application = get_application_model().objects.filter(client_id=client_id).first()
        error = OAuthToolkitError(error=unsupported, redirect_uri=redirect_uri)
        return self.error_response(error, application)

    @classmethod
    def as_view(cls, **initkwargs):
        # CSRF is enforced on the consent form only (see dispatch): an authorization
        # request sent by POST (OpenID Connect Core 1.0 section 3.1.2.1) comes from
        # the client's site and carries no CSRF token. Exempting the view here,
        # rather than decorating dispatch, keeps the exemption when a subclass
        # overrides dispatch.
        return csrf_exempt(super().as_view(**initkwargs))

    def is_consent_submission(self, request: http.HttpRequest) -> bool:
        """Whether a ``POST`` submits the consent form rather than an authorization request.

        OpenID Connect Core 1.0 section 3.1.2.1 requires the authorization endpoint to
        accept the authorization request by ``POST`` as well as ``GET``, and the consent
        form posts back to the same endpoint. A consent submission is recognized by what
        only it carries: the form's ``allow`` field or a CSRF token, in the
        ``csrfmiddlewaretoken`` field or the CSRF header. Every other ``POST`` is an
        authorization request. Override this if a custom consent form submits neither.

        A consent submission has its CSRF token checked; an authorization request has
        none to check. That is safe because an authorization request is only redirected
        to its ``GET`` form, which a cross-site page can link to anyway.
        """
        return (
            "allow" in request.POST
            or "csrfmiddlewaretoken" in request.POST
            or settings.CSRF_HEADER_NAME in request.META
        )

    @method_decorator(csrf_protect)
    def _dispatch_csrf_protected(self, request: http.HttpRequest, *args, **kwargs) -> http.HttpResponse:
        """Dispatch a consent submission, or any other unsafe request, with CSRF protection.

        The view itself is exempt so an authorization request can be sent by ``POST``.
        """
        return super().dispatch(request, *args, **kwargs)

    @method_decorator(ensure_csrf_cookie)
    def _dispatch_with_csrf_cookie(self, request: http.HttpRequest, *args, **kwargs) -> http.HttpResponse:
        """Dispatch a safe request, which may render the consent form, setting the CSRF cookie.

        The consent submission's token is checked against that cookie, which the view,
        being exempt, would otherwise leave unset when ``CsrfViewMiddleware`` is not
        installed.
        """
        return super().dispatch(request, *args, **kwargs)

    @staticmethod
    def _get_form_url(request: http.HttpRequest) -> str:
        """Return the URL of an authorization request sent by ``POST``, sent by ``GET``.

        The form-serialized parameters join any query string, so a parameter sent in
        both is repeated, as it would be in a ``GET``.
        """
        parameters = {key: request.GET.getlist(key) for key in request.GET}
        for key, values in request.POST.lists():
            parameters.setdefault(key, []).extend(values)
        query = urlencode(parameters, doseq=True)
        return f"{escape_uri_path(request.path)}?{query}" if query else escape_uri_path(request.path)

    def dispatch(self, request: http.HttpRequest, *args, **kwargs) -> http.HttpResponse:
        if request.method == "POST" and not self.is_consent_submission(request):
            # An authorization request sent by POST (OpenID Connect Core 1.0
            # section 3.1.2.1) is redirected to the same request sent by GET, so
            # every step, consent included, sees the parameters exactly as for a
            # GET. A cross-site POST also arrives without a SameSite=Lax session
            # cookie, which the browser does send with the GET, so a signed-in
            # user is not taken for an anonymous one.
            return HttpResponseRedirect(self._get_form_url(request), status=303)
        if request.method not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            # The consent submission, and any other method that could submit the
            # form (FormView handles PUT like POST), keep their CSRF protection.
            return self._dispatch_csrf_protected(request, *args, **kwargs)
        # Request objects are rejected before LoginRequiredMixin can send the
        # user to log in (or answer prompt=none with login_required). HEAD is
        # included because Django's View routes it to get().
        if request.method in ("GET", "HEAD"):
            unsupported_response = self._reject_request_objects(request)
            if unsupported_response is not None:
                return unsupported_response
        return self._dispatch_with_csrf_cookie(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        par_response = self._handle_pushed_authorization_request(request)
        if par_response is not None:
            return par_response

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
        kwargs["response_mode"] = request.GET.get("response_mode")
        kwargs["state"] = credentials["state"]
        if "code_challenge" in credentials:
            kwargs["code_challenge"] = credentials["code_challenge"]
        if "code_challenge_method" in credentials:
            kwargs["code_challenge_method"] = credentials["code_challenge_method"]
        if "nonce" in credentials:
            kwargs["nonce"] = credentials["nonce"]
        if "claims" in credentials:
            kwargs["claims"] = json.dumps(credentials["claims"])
        # RFC 8707: Extract resource parameter(s) from request (oauthlib doesn't handle it)
        # Multiple resource parameters are allowed per RFC 8707
        if "resource" in request.GET:
            resource_list = request.GET.getlist("resource")
            # Reject malformed resource URIs up front so they are never stored
            # on the grant and surfaced again at token issuance.
            for resource_uri in resource_list:
                if not is_valid_resource_uri(resource_uri):
                    error = OAuthToolkitError(
                        error=CustomOAuth2Error(
                            error="invalid_target",
                            description=(
                                f"The resource '{resource_uri}' is not a valid resource indicator: "
                                "it must be an absolute URI with a scheme and host."
                            ),
                            # RFC 6749: error redirects must echo the client's state
                            state=credentials.get("state"),
                        ),
                        redirect_uri=credentials["redirect_uri"],
                    )
                    # Lets error_response encode it like the successful response.
                    error.oauthlib_error.response_type = credentials["response_type"]
                    error.oauthlib_error.response_mode = self.request.GET.get("response_mode")
                    return self.error_response(error, application)
            # For form display: store as space-separated string
            # Multiple resources are rare, but we need to preserve them
            kwargs["resource"] = " ".join(resource_list)
            # For skip_authorization path: add list to credentials
            credentials["resource"] = resource_list

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

            # Implicit and hybrid errors go in the fragment, like their successful
            # responses (OpenID Connect Core 3.2.2.6 and 3.3.2.6).
            redirect_to = add_params_to_authorization_redirect(
                redirect_uri,
                urlencode(response_parameters),
                credentials.get("response_type"),
                self.request.GET.get("response_mode"),
            )
            # RFC 9207 §2 requires `iss` on every authorization response returned
            # to the client, error responses included; the redirect URI used here
            # was validated against the registered client above.
            if oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS:
                issuer = oauth2_settings.oauth2_authorization_server_issuer(self.request)
                redirect_to = add_iss_to_redirect(redirect_to, issuer)
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
class TokenView(FormEncodedRequestMixin, AuthorizationServerViewMixin, View):
    """
    Implements an endpoint to provide access tokens

    The endpoint is used in the following flows:
    * Authorization code
    * Password
    * Client credentials
    * Device code flow (specifically for the device polling stage)
    """

    form_encoded_endpoint = "The OAuth 2.0 token endpoint (RFC 6749 section 3.2)"

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
class RevokeTokenView(FormEncodedRequestMixin, AuthorizationServerViewMixin, View):
    """
    Implements an endpoint to revoke access or refresh tokens
    """

    form_encoded_endpoint = "The OAuth 2.0 token revocation endpoint (RFC 7009 section 2.1)"

    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_revocation_response(request)
        response = HttpResponse(content=body or "", status=status)

        for k, v in headers.items():
            response[k] = v
        return response
