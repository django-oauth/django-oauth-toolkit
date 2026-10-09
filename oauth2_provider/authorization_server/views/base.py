import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urlencode, urlparse

from django import http
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import redirect_to_login
from django.core import signing
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, QueryDict
from django.shortcuts import resolve_url
from django.urls.exceptions import NoReverseMatch
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import escape_uri_path
from django.views.decorators.csrf import csrf_exempt, csrf_protect, requires_csrf_token
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, View
from oauthlib.common import Request as OauthlibRequest
from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error, InvalidRequestError, OAuth2Error
from oauthlib.oauth2.rfc8628 import errors as rfc8628_errors
from oauthlib.openid.connect.core.exceptions import (
    InvalidRequestObject,
    RequestNotSupported,
    RequestURINotSupported,
)

from oauth2_provider.authorization_server import par, stored_requests
from oauth2_provider.authorization_server.forms import AllowForm
from oauth2_provider.authorization_server.oidc import request_objects
from oauth2_provider.authorization_server.oidc.claims import (
    PROTOCOL_CLAIMS,
    is_subset_claims_request,
    normalize_claims_request,
    requested_claim_names,
    safe_normalize_claims_request,
)
from oauth2_provider.authorization_server.oidc.max_age import INVALID_MAX_AGE_DESCRIPTION, is_valid_max_age
from oauth2_provider.authorization_server.response_modes import add_params_to_authorization_redirect
from oauth2_provider.authorization_server.sessions import (
    get_session_authentication_event,
    get_session_authentication_time,
)
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


if TYPE_CHECKING:
    from oauth2_provider.models import AbstractApplication


log = logging.getLogger("oauth2_provider")

# Where AuthorizationView records that it sent the user to log in, and how long
# that record lets a login count as the one it asked for.
REAUTHENTICATION_SESSION_KEY = "_oauth2_provider_reauthentication"
REAUTHENTICATION_WINDOW_SECONDS = 300
REAUTHENTICATION_RECORD_LIMIT = 10


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
            "claims_request": self.oauth2_data.get("claims_request", None),
            "acr_values": self.oauth2_data.get("acr_values", None),
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
        # form posts back to still carries it, except after a stored request.
        response_mode = form.cleaned_data.get("response_mode") or self.request.GET.get("response_mode")
        if response_mode:
            credentials["response_mode"] = response_mode
        if form.cleaned_data.get("code_challenge", False):
            credentials["code_challenge"] = form.cleaned_data.get("code_challenge")
        if form.cleaned_data.get("code_challenge_method", False):
            credentials["code_challenge_method"] = form.cleaned_data.get("code_challenge_method")
        if form.cleaned_data.get("nonce", False):
            credentials["nonce"] = form.cleaned_data.get("nonce")
        if oauth2_settings.OIDC_CLAIMS_PARAMETER_ENABLED and form.cleaned_data.get("allow"):
            # Only an approval releases claims; a denial needs no claims request.
            claims = self._consented_claims(form.cleaned_data)
            if claims is None:
                if not form.cleaned_data.get("claims_request"):
                    log.warning(
                        "The consent form posted no claims_request field. With "
                        "OIDC_CLAIMS_PARAMETER_ENABLED, a custom authorize.html must post it back."
                    )
                return self._fatal_invalid_request("The claims posted with the consent form are not valid.")
            # Always set, so oauthlib never falls back to a claims query parameter.
            credentials["claims"], credentials["claims_original"] = claims
        elif form.cleaned_data.get("claims", False):
            credentials["claims"] = form.cleaned_data.get("claims")
        if form.cleaned_data.get("acr_values", False):
            credentials["acr_values"] = form.cleaned_data.get("acr_values")
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

    # The request parameters a signed claims request is bound to, so one signed for
    # another authorization request cannot be posted with this one. A client that
    # sends none of state, nonce and code_challenge cannot tell its requests apart,
    # and neither can this binding. response_type is bound because, without id_token,
    # oauthlib handles an implicit request with the OAuth 2.0 grant, which never
    # checks the claims request.
    _CLAIMS_REQUEST_BINDING = (
        "client_id",
        "redirect_uri",
        "response_type",
        "state",
        "nonce",
        "code_challenge",
    )
    _CLAIMS_REQUEST_SALT = "oauth2_provider.claims_request"

    @classmethod
    def _claims_request_binding(cls, parameters: dict) -> dict:
        # Compared with form fields, which strip surrounding whitespace.
        bound = {name: str(parameters.get(name) or "").strip() for name in cls._CLAIMS_REQUEST_BINDING}
        # The order of the values of response_type does not matter (RFC 6749 §3.1.1).
        bound["response_type"] = " ".join(sorted(bound["response_type"].split()))
        return bound

    @classmethod
    def _sign_claims_request(cls, claims: dict | None, parameters: dict) -> str:
        """Sign the claims request (OIDC Core 5.5) shown on the consent page."""
        bound = cls._claims_request_binding(parameters)
        return signing.dumps({"claims": claims or {}, "bound": bound}, salt=cls._CLAIMS_REQUEST_SALT)

    @classmethod
    def _consented_claims(cls, cleaned_data: dict) -> tuple[dict, dict] | None:
        """
        The claims request to authorize after consent, as ``(consented, original)``
        normalized claims requests, or ``None`` if the form was tampered with.

        The hidden ``claims`` field may drop individual claim requests the End-User
        declined (partial consent), but must otherwise match the signed original:
        it can never add or alter one. The original still decides the ``sub`` and
        essential ``acr`` checks, which concern the authentication, not the release.
        """
        try:
            signed = signing.loads(cleaned_data.get("claims_request") or "", salt=cls._CLAIMS_REQUEST_SALT)
        except signing.BadSignature:
            return None
        if not isinstance(signed, dict) or signed.get("bound") != cls._claims_request_binding(cleaned_data):
            return None
        original = safe_normalize_claims_request(signed.get("claims"))
        if original and "openid" not in (cleaned_data.get("scope") or "").split():
            # oauthlib checks the claims request (sub, essential acr) only for an
            # OpenID request, so the openid scope can't be dropped while one stands.
            return None
        try:
            consented = normalize_claims_request(json.loads(cleaned_data.get("claims") or "null"))
        except (ValueError, RecursionError, InvalidRequestError):
            # RecursionError: JSON nested deeper than the parser can follow.
            return None
        if not is_subset_claims_request(consented, original):
            return None
        return consented, original

    def _releasable_claim_names(
        self, application: "AbstractApplication", scopes: list[str], credentials: dict
    ) -> list[str]:
        """
        The individual claims requested through the ``claims`` parameter that could be
        released to the client, for the consent page: those ``get_requested_claims``
        keeps that are standard claims (``oidc_claim_scope``) or that ``get_claim_dict``
        supplies, other than the protocol claims.

        The hooks see the authorization request parameters oauthlib validated
        (``credentials``), as ``create_authorization_response`` sets them, but no other
        parameter the client sent.

        Claim names are chosen by the client, so listing only names the validator
        knows keeps a crafted name from reading like part of the page.
        """
        from oauth2_provider.oauth2_validators import OAuth2Validator

        claims = credentials.get("claims")
        validator = self.get_validator_class()()
        try:
            # A savepoint on the default database, so a database error in the
            # validator leaves the request's transaction usable. The request carries
            # no URI: every attribute the hooks read is set here.
            with transaction.atomic():
                oauthlib_request = OauthlibRequest("")
                for name, value in credentials.items():
                    if name != "request":
                        setattr(oauthlib_request, name, value)
                oauthlib_request.user = self.request.user
                oauthlib_request.client = application
                oauthlib_request.client_id = application.client_id
                oauthlib_request.scopes = scopes
                oauthlib_request.claims = claims
                known = set(validator.oidc_claim_scope or OAuth2Validator.oidc_claim_scope)
                known.update(validator.get_claim_dict(oauthlib_request))
                requested = set()
                for target in ("id_token", "userinfo"):
                    requested.update(validator.get_requested_claims(oauthlib_request, target))
        except Exception:
            # Never understate what is requested: list every name if the validator
            # can't answer outside a token request.
            log.exception("Could not work out which requested claims the validator supplies.")
            return sorted(requested_claim_names(claims))
        return sorted((requested & known) - set(PROTOCOL_CLAIMS))

    def _fatal_invalid_request(self, description: str) -> http.HttpResponse:
        """Render a non-redirecting ``invalid_request`` authorization error.

        Used for stored request_uri and PAR-enforcement failures: there is no validated
        redirect_uri to trust, so the error is shown to the resource owner rather
        than redirected (which would risk an open redirect).
        """
        error = FatalClientError(error=CustomOAuth2Error(error="invalid_request", description=description))
        return self.error_response(error, application=None)

    def _resolve_stored_request_uri(
        self, request: http.HttpRequest, request_uri: str
    ) -> http.HttpResponse | None:
        """Replace an incoming ``request_uri`` with the parameters of the stored
        authorization request it refers to (RFC 9126 §4), or return an error response.

        The consume/binding/expiry logic lives in
        :mod:`oauth2_provider.authorization_server.stored_requests`; here we only
        re-inject the resolved parameters into the request and render errors.
        """
        try:
            parameters = stored_requests.consume_authorization_request(
                request_uri, request.GET.get("client_id")
            )
        except stored_requests.StoredAuthorizationRequestError as error:
            return self._fatal_invalid_request(error.description)
        self.stored_request = True
        self.stored_request_uri = request_uri
        # Re-inject the stored parameters so the existing authorization flow, which
        # reads from the query string, proceeds unchanged. Any parameters supplied
        # alongside request_uri are intentionally ignored: the stored request was
        # validated in full before it was stored and is authoritative (RFC 9126),
        # which prevents parameter injection.
        self._replace_query(request, parameters)
        return None

    @staticmethod
    def _replace_query(request: http.HttpRequest, parameters: dict) -> None:
        """Replace the request's query string, which the authorization flow reads from."""
        query_string = urlencode(parameters, doseq=True)
        request.GET = QueryDict(query_string, mutable=False)
        request.META["QUERY_STRING"] = query_string

    def _resolve_stored_request_or_enforce_par(self, request: http.HttpRequest) -> http.HttpResponse | None:
        """Resolve a stored ``request_uri`` or enforce mandatory PAR (RFC 9126).

        Returns an error response to short-circuit the view, or ``None`` to continue
        with the (possibly rewritten) request.
        """
        request_uri = request.GET.get("request_uri")
        # Only stored-request URIs are resolved here; any other request_uri (OpenID
        # Connect Core 1.0 section 6.2) is handled by _handle_request_objects.
        if stored_requests.is_stored_request_uri(request_uri):
            return self._resolve_stored_request_uri(request, request_uri)
        if par.pushed_authorization_required(request.GET.get("client_id")):
            if oauth2_settings.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS:
                message = "This authorization server requires pushed authorization requests."
            else:
                message = "Pushed authorization requests are required for this client."
            return self._fatal_invalid_request(message)
        return None

    def _handle_request_objects(self, request: http.HttpRequest) -> http.HttpResponse | None:
        """Resolve or reject the ``request`` and non-stored ``request_uri`` parameters.

        With ``OIDC_REQUEST_OBJECTS_ENABLED`` the request object (OpenID Connect
        Core 1.0 section 6) is validated, the authorization request is assembled
        from it and the query parameters (section 6.3.3), and
        :meth:`_store_resolved_request` stores it and redirects the user agent
        back to this endpoint with a reference to it. The rest of the flow,
        including the login redirect, the ``prompt`` handling and the consent
        form, then resolves it like any stored request, so the request object is
        resolved, and a ``request_uri`` fetched, exactly once, and its
        parameters never enter the URL. An invalid request object is
        answered with ``invalid_request_object``, ``invalid_request_uri`` or
        ``invalid_request``. Otherwise request objects
        are not supported, and such a request is answered with
        ``request_not_supported`` or ``request_uri_not_supported`` (section
        3.1.2.6). See :meth:`_request_object_error_response` for where errors go.

        This runs from :meth:`dispatch`, before the login gate: the request is
        validated before the end-user is authenticated (sections 3.1.2.2 and
        3.1.2.3). An invalid request object is therefore reported as such even
        for an anonymous request, including a ``prompt=none`` one, rather than
        sent to a login page or answered with ``login_required``; a valid one is
        stored, and goes through login and ``prompt`` handling from there.

        Returns ``None`` to leave the request to the normal flow: when it carries
        neither parameter, when its ``request_uri`` refers to a stored request (the
        stored request is authoritative, and never carries either parameter), and
        when the client must use PAR, which the PAR enforcement in :meth:`get`
        reports instead.
        """
        request_uri = request.GET.get("request_uri")
        if stored_requests.is_stored_request_uri(request_uri):
            return None
        # Any non-empty value counts, not just the last one, so a repeated
        # parameter is refused rather than hidden behind an empty last value.
        has_request = any(request.GET.getlist("request"))
        if not has_request and not any(request.GET.getlist("request_uri")):
            return None
        if par.pushed_authorization_required(request.GET.get("client_id")):
            return None
        if not request_objects.request_objects_enabled():
            error_class = RequestNotSupported if has_request else RequestURINotSupported
            return self._request_object_error_response(request, error_class)

        application = self._load_request_object_client(request)
        if application is None:
            # No client to verify the request object for; the outer parameters
            # decide how this is reported (an unknown client is never redirected).
            return self._request_object_error_response(request, InvalidRequestObject)
        try:
            parameters = request_objects.resolve_request_object(
                dict(request.GET.lists()), application, request
            )
        except request_objects.RequestObjectError as error:
            return self._request_object_error_response(request, error.error_class, error.description)
        return self._store_resolved_request(request, application, parameters)

    def _store_resolved_request(
        self, request: http.HttpRequest, application: "AbstractApplication", parameters: dict[str, list[str]]
    ) -> http.HttpResponse:
        """Store the assembled authorization request and redirect to its reference.

        The assembled request never enters the URL (OpenID Connect Core 1.0
        section 6): it is kept on the server in the stored-request store and the
        user agent is redirected to this endpoint with only ``client_id`` and a
        single-use ``request_uri``, which the rest of the flow resolves like any
        stored request. It is first validated in full, as the store requires
        (see :mod:`oauth2_provider.authorization_server.stored_requests`), so an
        invalid request is reported now, before the end-user is asked to log in
        (sections 3.1.2.2 and 3.1.2.3), with the response :meth:`get` would give.

        An anonymous end-user's stored request is only a reference until they log
        in, so its ``prompt`` is acted on here: ``none`` is answered with
        ``login_required`` and ``create`` sends them to register, returning to
        the stored request. ``login`` and ``max_age`` are handled as for any
        stored request.
        """
        self._replace_query(request, parameters)
        try:
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolkitError as error:
            return self.error_response(error, application=None)
        oidc_request = oauth2_settings.OIDC_ENABLED and "openid" in scopes
        repeated = self._repeated_authentication_parameter(oidc_request)
        if repeated is not None:
            return self._invalid_request_response(credentials, f"{repeated} must not be repeated.")
        max_age = request.GET.get("max_age")
        if oidc_request and max_age and not is_valid_max_age(max_age):
            return self._invalid_request_response(credentials, INVALID_MAX_AGE_DESCRIPTION)

        prompt = set(request.GET.get("prompt", "").split())
        anonymous = not request.user.is_authenticated
        if anonymous and "none" in prompt:
            return self._login_required_response(credentials)
        registration_url = None
        if anonymous and "create" in prompt:
            unsupported = self._prompt_create_unsupported_response()
            if unsupported is not None:
                return unsupported
            registration_url = self._registration_url()

        # The store's shape: each name's last value, except resource (RFC 8707).
        stored = {
            name: values if name == "resource" else values[-1]
            for name, values in parameters.items()
            if name not in par.CLIENT_AUTH_PARAMETERS
        }
        request_uri = stored_requests.store_authorization_request(
            application.client_id,
            stored,
            expires_in=oauth2_settings.OIDC_REQUEST_OBJECT_STORE_LIFETIME_SECONDS,
        )
        reference = {"client_id": [application.client_id], "request_uri": [request_uri]}
        location = f"{escape_uri_path(request.path)}?{urlencode(reference, doseq=True)}"
        if registration_url is not None:
            # As handle_no_permission does for a stored request, so the login that
            # registering ends with satisfies the stored prompt and max_age.
            self._request_reauthentication(reference, fresh=False)
            return self._registration_redirect(registration_url, request.build_absolute_uri(location))
        return HttpResponseRedirect(location)

    def _load_request_object_client(self, request: http.HttpRequest) -> "AbstractApplication | None":
        """Load the client a request object is verified for, as the validator does.

        Goes through the validator's ``_load_application``, so a client_id that
        is a Client ID Metadata Document URL is resolved like at any other
        point of the flow, and an unusable application is not returned.
        """
        client_id = request.GET.get("client_id")
        if not client_id:
            return None
        # Built with the method and headers the rest of the flow passes, so
        # is_usable() overrides and CIMD permission classes see the same request.
        # The query is re-encoded from its decoded form: oauthlib refuses a
        # malformed percent escape, which Django's decoding tolerates.
        core = self.get_oauthlib_core()
        uri = f"{request.path}?{urlencode(list(request.GET.lists()), doseq=True)}"
        oauthlib_request = OauthlibRequest(
            uri,
            http_method=request.method,
            body=urlencode(core.extract_body(request)),
            headers=core.extract_headers(request),
        )
        oauthlib_request.client = None
        return self.get_validator_class()()._load_application(client_id, oauthlib_request)

    def _request_object_error_response(
        self, request: http.HttpRequest, error_class: type[OAuth2Error], description: str | None = None
    ) -> http.HttpResponse:
        """Answer a request whose request object is unsupported or invalid.

        The rest of the request is validated without ``request`` and
        ``request_uri`` so the error is only redirected to a redirect URI the
        client registered and sent with the OAuth 2.0 syntax (or its only
        registered one, when none was sent), never one only the request object
        named, with the client's ``state`` echoed. Otherwise it is
        rendered like any other fatal authorization error.
        """
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
            # the request object (a nonce, say), so report the request object
            # error rather than the symptom.
            oauthlib_error: OAuth2Error = error.oauthlib_error
            client_id = oauthlib_error.client_id
            redirect_uri = oauthlib_error.redirect_uri
            state = oauthlib_error.state

        request_object_error = error_class(description=description, state=state)
        # Carry what oauthlib records from a request, so the error is encoded with
        # the response mode the client's response type calls for.
        request_object_error.client_id = client_id
        request_object_error.response_type = request.GET.get("response_type")
        request_object_error.response_mode = request.GET.get("response_mode")
        if not redirect_uri:
            return self.error_response(FatalClientError(error=request_object_error), application=None)
        application = get_application_model().objects.filter(client_id=client_id).first()
        error = OAuthToolkitError(error=request_object_error, redirect_uri=redirect_uri)
        return self.error_response(error, application)

    @classmethod
    def as_view(cls, **initkwargs: Any) -> Callable[..., http.HttpResponse]:
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

    @method_decorator(requires_csrf_token)
    def _dispatch_with_csrf_token(self, request: http.HttpRequest, *args, **kwargs) -> http.HttpResponse:
        """Dispatch a safe request, which may render the consent form, with CSRF token support.

        The consent submission's token is checked against the CSRF cookie. When the
        consent form uses the token, this sets that cookie, which the view, being exempt,
        would otherwise leave unset when ``CsrfViewMiddleware`` is not installed; other
        responses, such as redirects, are left without it.
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
        # Whether the request being authorized was resolved from a stored
        # request_uri, which can be used only once (RFC 9126 section 4).
        self.stored_request = False
        self.stored_request_uri = None
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
        # Request objects are resolved (or rejected) before LoginRequiredMixin can
        # send the user to log in (or answer prompt=none with login_required).
        # HEAD is included because Django's View routes it to get(). A resolved
        # request object redirects to a stored request, so the consent POST never
        # carries one.
        if request.method in ("GET", "HEAD"):
            request_object_response = self._handle_request_objects(request)
            if request_object_response is not None:
                return request_object_response
        return self._dispatch_with_csrf_token(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        stored_request_response = self._resolve_stored_request_or_enforce_par(request)
        if stored_request_response is not None:
            return stored_request_response

        try:
            scopes, credentials = self.validate_authorization_request(request)
        except OAuthToolkitError as error:
            # Application is not available at this time.
            return self.error_response(error, application=None)

        oidc_request = oauth2_settings.OIDC_ENABLED and "openid" in scopes
        repeated = self._repeated_authentication_parameter(oidc_request)
        if repeated is not None:
            return self._invalid_request_response(credentials, f"{repeated} must not be repeated.")
        # The request is validated before the user is asked to authenticate
        # (OpenID Connect Core 1.0 sections 3.1.2.2 and 3.1.2.3).
        max_age = request.GET.get("max_age")
        if oidc_request and max_age and not is_valid_max_age(max_age):
            return self._invalid_request_response(credentials, INVALID_MAX_AGE_DESCRIPTION)

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
        # A login this view asked for satisfies the login prompt and max_age
        # of the request it was asked for; both stay in the request until then.
        # Coming back to that request without the fresh login it still needs
        # gets login_required (OpenID Connect Core 1.0 section 3.1.2.1) rather
        # than another trip to the login page, so the flow can never loop.
        if self.stored_request:
            returning = {"request_uri": [self.stored_request_uri]}
        else:
            returning = dict(request.GET.lists())
        reauthentication = self._reauthentication_outcome(returning)
        reauthenticated = reauthentication is True
        returned_without_login = reauthentication is False
        if "login" in prompt and not reauthenticated:
            if returned_without_login:
                return self._login_required_response(credentials)
            return self.handle_prompt_login()
        if oidc_request:
            max_age_response = self._handle_max_age(
                credentials, prompt, reauthenticated, returned_without_login
            )
            if max_age_response is not None:
                return max_age_response

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
        if oauth2_settings.OIDC_CLAIMS_PARAMETER_ENABLED:
            kwargs["claims_request"] = self._sign_claims_request(credentials.get("claims"), credentials)
        if request.GET.get("acr_values"):
            kwargs["acr_values"] = request.GET["acr_values"]
        # OIDC Core 5.5: show the End-User the individual claims requested on top of
        # the scopes, as they can be released beyond what the scopes cover.
        requested_claims = (
            requested_claim_names(credentials.get("claims"))
            if oauth2_settings.OIDC_CLAIMS_PARAMETER_ENABLED
            else set()
        )
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

                # check past authorizations regarded the same scopes as the current one,
                # and the same individual claims (OIDC Core 5.5), so newly requested
                # claims are always presented to the End-User
                for token in tokens:
                    if token.allow_scopes(scopes) and requested_claims <= requested_claim_names(token.claims):
                        uri, headers, body, status = self.create_authorization_response(
                            request=self.request,
                            scopes=" ".join(scopes),
                            credentials=credentials,
                            allow=True,
                        )
                        return self.redirect(uri, application)

        except OAuthToolkitError as error:
            return self.error_response(error, application)

        # prompt=none must not display a consent page (OpenID Connect Core
        # 1.0 section 3.1.2.1). Reaching here means the user is authenticated
        # and the client still needs consent, so answer consent_required
        # (section 3.1.2.6) instead of rendering the form.
        if "none" in prompt:
            return self._login_required_response(credentials, error="consent_required")

        # Only now that the consent page is rendered, so skipped consent pays nothing.
        kwargs["requested_claims"] = (
            self._releasable_claim_names(application, scopes, credentials) if requested_claims else []
        )
        return self.render_to_response(self.get_context_data(**kwargs))

    def handle_prompt_login(self) -> HttpResponse:
        return self._redirect_to_login()

    def _redirect_to_login(self) -> HttpResponse:
        """Send the user to log in, returning to this authorization request after.

        Used for ``prompt=login`` and an elapsed ``max_age``.

        The return URL keeps the whole request, ``prompt`` and ``max_age``
        included: the login is only taken as satisfying them once
        :meth:`_reauthentication_outcome` has verified it, so following the
        return URL without logging in gains nothing.

        A stored request has already used up its ``request_uri`` (RFC 9126
        section 4), so its parameters are stored again for the same client and
        the return URL carries only the new ``request_uri``: the request stays
        on the server, and a client that must use PAR can still complete it.
        """
        parameters = dict(self.request.GET.lists())
        if self.stored_request:
            client_id = self.request.GET["client_id"]
            # These parameters were resolved from the store, so they were validated
            # in full when first stored. Stored in the shape the store documents.
            stored = {key: values if key == "resource" else values[-1] for key, values in parameters.items()}
            request_uri = stored_requests.store_authorization_request(
                client_id, stored, expires_in=oauth2_settings.PAR_REQUEST_URI_LIFETIME_SECONDS
            )
            parameters = {"client_id": [client_id], "request_uri": [request_uri]}
        self._request_reauthentication(parameters, fresh=True)

        path = escape_uri_path(self.request.path)
        resolved_login_url = resolve_url(self.get_login_url())

        # If the login url is the same scheme and net location then use the
        # path as the "next" url.
        login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
        current_scheme, current_netloc = urlparse(self.request.build_absolute_uri(path))[:2]
        if not (
            (not login_scheme or login_scheme == current_scheme)
            and (not login_netloc or login_netloc == current_netloc)
        ):
            path = self.request.build_absolute_uri(path)

        return redirect_to_login(
            f"{path}?{urlencode(parameters, doseq=True)}",
            resolved_login_url,
            self.get_redirect_field_name(),
        )

    def _handle_max_age(
        self, credentials: dict, prompt: set, reauthenticated: bool, returned_without_login: bool
    ) -> HttpResponse | None:
        """Re-authenticate the user if this session was authenticated more than
        ``max_age`` seconds ago (OpenID Connect Core 1.0 section 3.1.2.1).

        The time is that of the login that authenticated the current session;
        a session whose login time is unknown counts as not authenticated
        recently enough. ``max_age=0`` is treated as ``prompt=login``, as the
        specification says it is equivalent to: only a login this view asked
        for satisfies it. That login also satisfies any other value, so a slow
        return from the login page does not ask again. ``prompt=none``, and a
        user who came back from the login page this view sent them to without
        logging in, get a ``login_required`` error instead.

        Returns ``None`` when ``max_age`` is absent or satisfied.
        """
        max_age = self.request.GET.get("max_age")
        if not max_age:
            return None
        if reauthenticated:
            return None
        auth_time = get_session_authentication_time(self.request)
        # More significant digits than this is over 300 years: no limit, and
        # int() is never asked to convert an arbitrarily long string. No
        # significant digits is max_age=0, which only a new login meets.
        seconds = max_age.lstrip("0")
        if (
            seconds
            and auth_time is not None
            and (len(seconds) > 10 or time.time() - auth_time <= int(seconds))
        ):
            return None
        if "none" in prompt or returned_without_login:
            return self._login_required_response(credentials)
        return self._redirect_to_login()

    def _repeated_authentication_parameter(self, oidc_request: bool) -> str | None:
        """The name of ``prompt`` or (for an OpenID Connect request) ``max_age``
        if the request repeats it, else ``None``.

        Parameters must not be included more than once (RFC 6749 section 3.1);
        oauthlib checks the ones it reads, and these two decide whether the
        user has to log in, so a repeat must not silently pick one value.
        """
        names = ("prompt", "max_age") if oidc_request else ("prompt",)
        if oidc_request and oauth2_settings.OIDC_CLAIMS_PARAMETER_ENABLED:
            # The claims request decides the sub and essential acr checks.
            names += ("claims",)
        for name in names:
            if len(self.request.GET.getlist(name)) > 1:
                return name
        return None

    def _invalid_request_response(self, credentials: dict, description: str) -> HttpResponse:
        """Redirect an ``invalid_request`` error to the client."""
        error = OAuthToolkitError(
            error=InvalidRequestError(
                description=description,
                state=credentials.get("state"),
            ),
            redirect_uri=credentials["redirect_uri"],
        )
        # Lets error_response encode it like the successful response.
        error.oauthlib_error.response_type = credentials["response_type"]
        error.oauthlib_error.response_mode = self.request.GET.get("response_mode")
        application = get_application_model().objects.get(client_id=credentials["client_id"])
        return self.error_response(error, application)

    @staticmethod
    def _reauthentication_binding(parameters: dict[str, list[str]]) -> str:
        """Identify the authorization request that the user returns with.

        A stored request is identified by its ``request_uri``, and any other
        by its parameters. ``prompt`` is left out, so a login asked for by an
        anonymous request without one still matches.
        """
        request_uri = parameters.get("request_uri")
        if request_uri and stored_requests.is_stored_request_uri(request_uri[-1]):
            identity = ["request_uri", request_uri[-1]]
        else:
            identity = sorted([key, values] for key, values in parameters.items() if key != "prompt")
        return hashlib.sha256(json.dumps(identity).encode()).hexdigest()

    def _request_reauthentication(self, parameters: dict[str, list[str]], fresh: bool) -> None:
        """Record in the session that this view sent the user to log in for
        the authorization request with ``parameters``.

        :meth:`_reauthentication_outcome` uses it to tell whether the user
        logged in since, so a login asked for by ``prompt=login`` or
        ``max_age`` is not asked for a second time. ``fresh`` is set when the
        view asked for a new login (:meth:`_redirect_to_login`) rather than
        for a login of any kind. The record keeps the identifier of the login
        that authenticated the session at the time, so that any later login,
        however soon, can be told from it.

        Each pending request has its own record, so a second tab does not
        discard the first one's; records older than
        ``REAUTHENTICATION_WINDOW_SECONDS`` are dropped, and at most
        ``REAUTHENTICATION_RECORD_LIMIT`` are kept.
        """
        now = time.time()
        records = {
            binding: record
            for binding, record in self._reauthentication_records().items()
            if now - record["at"] <= REAUTHENTICATION_WINDOW_SECONDS
        }
        records[self._reauthentication_binding(parameters)] = {
            "at": now,
            "event": get_session_authentication_event(self.request),
            "fresh": fresh,
        }
        newest = sorted(records.items(), key=lambda item: item[1]["at"])[-REAUTHENTICATION_RECORD_LIMIT:]
        self.request.session[REAUTHENTICATION_SESSION_KEY] = dict(newest)

    def _reauthentication_records(self) -> dict[str, dict]:
        """The well-formed re-login records in the session, by request binding."""
        records = self.request.session.get(REAUTHENTICATION_SESSION_KEY)
        if not isinstance(records, dict):
            return {}
        return {
            binding: record
            for binding, record in records.items()
            if isinstance(record, dict) and isinstance(record.get("at"), (int, float))
        }

    def _reauthentication_outcome(self, parameters: dict[str, list[str]]) -> bool | None:
        """Whether the user logged in after this view sent them to log in for
        the authorization request with ``parameters``.

        ``None`` when there is no such record: none was made, it was made for
        another request, or more than ``REAUTHENTICATION_WINDOW_SECONDS`` ago.
        Otherwise the record is removed, so it is used at most once, and the
        result is ``True`` when the session has been authenticated by a login
        other than the one it had when the record was made. Logins are told
        apart by identifier, not by time, so one in the same clock tick still
        counts and the old one never does. When there was no new login, the
        result is ``False`` if the view had asked for one, and ``None`` if it
        had only sent an anonymous user to log in by some means that does not
        go through :func:`django.contrib.auth.login`.

        Other pending requests (a second tab, say) keep their own records. A
        login in another browser does not count, since it authenticates
        another session.
        """
        records = self._reauthentication_records()
        binding = self._reauthentication_binding(parameters)
        requested = records.pop(binding, None)
        if requested is None:
            if REAUTHENTICATION_SESSION_KEY in self.request.session and binding in (
                self.request.session[REAUTHENTICATION_SESSION_KEY] or {}
            ):
                # A malformed record for this request: drop it, as if none.
                self.request.session[REAUTHENTICATION_SESSION_KEY] = records
            return None
        self.request.session[REAUTHENTICATION_SESSION_KEY] = records
        if time.time() - requested["at"] > REAUTHENTICATION_WINDOW_SECONDS:
            return None
        event = get_session_authentication_event(self.request)
        if event is not None and event != requested.get("event"):
            return True
        return False if requested.get("fresh") else None

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
        unsupported = self._prompt_create_unsupported_response()
        if unsupported is not None:
            return unsupported

        # The no-op for authenticated sessions comes before the registration
        # URL is resolved: these requests never redirect to registration, so
        # a misconfigured URL must not break them. Anonymous create requests
        # below still surface the misconfiguration loudly.
        if self.request.user.is_authenticated:
            return None

        registration_url = self._registration_url()

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
        return self._registration_redirect(registration_url, next_url)

    @staticmethod
    def _prompt_create_unsupported_response() -> JsonResponse | None:
        """The answer to ``prompt=create`` when it is not supported, else ``None``."""
        # Per Prompt Create 1.0 section 4.1.1, an OP receiving a prompt value it
        # does not support (one not declared in prompt_values_supported) SHOULD
        # respond with HTTP 400 and an error value of invalid_request.
        if not oauth2_settings.OIDC_RP_INITIATED_REGISTRATION_ENABLED:
            return JsonResponse(
                {"error": "invalid_request", "error_description": "prompt=create is not supported"},
                status=400,
            )
        return None

    @staticmethod
    def _registration_url() -> str:
        """Resolve ``OIDC_RP_INITIATED_REGISTRATION_URL``."""
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
            return resolve_url(registration_location)
        except NoReverseMatch as exc:
            raise ImproperlyConfigured(
                f"OIDC_RP_INITIATED_REGISTRATION_URL {registration_location!r} could not be "
                "resolved to a registration page."
            ) from exc

    @staticmethod
    def _registration_redirect(registration_url: str, next_url: str) -> HttpResponseRedirect:
        """Send the user to register, returning to *next_url* afterwards."""
        # Merge next into the registration URL's query so an existing query
        # string or fragment in the configured URL is preserved.
        parsed_registration = urlparse(registration_url)
        registration_query = dict(parse_qsl(parsed_registration.query))
        registration_query["next"] = next_url
        redirect_to = parsed_registration._replace(query=urlencode(registration_query)).geturl()
        return HttpResponseRedirect(redirect_to)

    def _login_required_response(self, credentials: dict, error: str = "login_required") -> HttpResponse:
        """Redirect a ``login_required`` or ``consent_required`` error to the
        client (OpenID Connect Core 1.0 section 3.1.2.6), for a request that
        oauthlib has validated.
        """
        # oauthlib has confirmed redirect_uri is registered for the client.
        redirect_uri = credentials["redirect_uri"]
        application = get_application_model().objects.get(client_id=credentials["client_id"])

        response_parameters = {"error": error}

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
        # was validated against the registered client.
        if oauth2_settings.COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS:
            issuer = oauth2_settings.oauth2_authorization_server_issuer(self.request)
            redirect_to = add_iss_to_redirect(redirect_to, issuer)
        return self.redirect(redirect_to, application)

    def handle_no_permission(self):
        """
        Generate response for unauthorized users.

        If the prompt parameter contains none, then we redirect with an error
        code as defined by OpenID Connect Core 1.0 section 3.1.2.6
        (Authentication Error Response)
        <https://openid.net/specs/openid-connect-core-1_0.html#AuthError>.

        If the prompt parameter contains create, then we redirect to the
        registration page.

        If the prompt parameter contains login, then we redirect to the login
        flow recording that the login was asked for, so the user is not sent
        to log in a second time when they return to this endpoint
        authenticated.

        Some code copied from OAuthLibMixin.error_response, but that is designed
        to operate on OAuth2Error from oauthlib wrapped in a OAuthToolkitError
        """
        # prompt is a space-delimited, case-sensitive list of ASCII values
        # (OpenID Connect Core 1.0 section 3.1.2.1).
        max_age = self.request.GET.get("max_age")
        request_uri = self.request.GET.get("request_uri", "")
        malformed = bool(max_age) and not is_valid_max_age(max_age)
        repeated = any(len(self.request.GET.getlist(name)) > 1 for name in ("prompt", "max_age"))
        if (malformed or repeated) and not stored_requests.is_stored_request_uri(request_uri):
            # The request is validated before the end-user is authenticated
            # (OpenID Connect Core 1.0 sections 3.1.2.2 and 3.1.2.3), so a
            # malformed or repeated max_age or prompt is reported now rather
            # than after a login. error_response never redirects to an
            # unregistered redirect_uri. A stored request is authoritative and
            # was validated in full before it was stored (see stored_requests).
            try:
                scopes, credentials = self.validate_authorization_request(self.request)
            except OAuthToolkitError as error:
                return self.error_response(error, application=None)
            oidc_request = oauth2_settings.OIDC_ENABLED and "openid" in scopes
            name = self._repeated_authentication_parameter(oidc_request)
            if name is not None:
                return self._invalid_request_response(credentials, f"{name} must not be repeated.")
            if malformed and oidc_request:
                return self._invalid_request_response(credentials, INVALID_MAX_AGE_DESCRIPTION)

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

            return self._login_required_response(credentials)

        # Lets get() count the login that follows (after registering, too) as
        # one it asked for, by max_age or by a stored request's prompt or
        # max_age (which are not in the query), so the user is not sent to log
        # in a second time. Other requests do not need it, and are left without
        # a session. A prompt=login redirect below records its own.
        if "max_age" in self.request.GET or stored_requests.is_stored_request_uri(request_uri):
            self._request_reauthentication(dict(self.request.GET.lists()), fresh=False)

        if "create" in prompt:
            # If prompt contains create and the user is not authenticated,
            # redirect to registration.
            return self.handle_prompt_create()

        if "login" in prompt:
            # handle_prompt_login records that the login was asked for, so the
            # one that follows satisfies the prompt still in the next URL.
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
