import calendar
import hashlib
import logging
import threading
import weakref
from collections import OrderedDict

from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpRequest, JsonResponse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from oauthlib.common import Request as OauthlibRequest

from oauth2_provider.core.backends_oauthlib import _AUTHENTICATED_CLIENT_ATTRIBUTE
from oauth2_provider.core.compat import login_not_required
from oauth2_provider.core.views import FormEncodedRequestMixin
from oauth2_provider.models import AbstractApplication, get_access_token_model
from oauth2_provider.resource_server.views.generic import ClientProtectedScopedResourceView


log = logging.getLogger(__name__)

# Stored under _AUTHENTICATED_CLIENT_ATTRIBUTE before the backend runs: still there
# afterwards means the backend did not report which client it authenticated.
_NOT_REPORTED = object()

# The backend classes already warned about, so that a backend which cannot report
# the authenticated client is logged once per process rather than on every
# introspection request. Keyed on the class object, so two classes sharing a
# qualified name (say, from one factory) are each reported, and held weakly, so
# classes created at run time do not accumulate. A class that cannot be a weak
# key, which in practice means one whose metaclass is unhashable (it defines
# __eq__ without __hash__), falls back to its qualified name.
_warned_backends: weakref.WeakKeyDictionary[type, set[str]] = weakref.WeakKeyDictionary()
_warned_backend_names: set[tuple[str, str]] = set()
_warned_backends_lock = threading.Lock()

_NOT_REPORTED_MESSAGE = (
    "Introspection refused on the client-authentication path: %s authenticated the client "
    "without OAuthLibCore.authenticate_client_request() recording which client it was, so "
    "that client cannot be checked for can_introspect (logged once per backend class)"
)
_REFUSED_MESSAGE = (
    "Introspection refused on the client-authentication path: %s reported success although "
    "OAuthLibCore.authenticate_client_request() did not authenticate the client, so no client "
    "is authorized (logged once per backend class)"
)


def _warn_backend_once(backend: type, message: str) -> None:
    """Log *message* about *backend*, once per backend class and message."""
    name = f"{backend.__module__}.{backend.__qualname__}"
    with _warned_backends_lock:
        try:
            seen = _warned_backends.setdefault(backend, set())
        except TypeError:
            if (name, message) in _warned_backend_names:
                return
            _warned_backend_names.add((name, message))
        else:
            if message in seen:
                return
            seen.add(message)
    log.warning(message, name)


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class IntrospectTokenView(FormEncodedRequestMixin, ClientProtectedScopedResourceView):
    """
    Implements an endpoint for token introspection based
    on RFC 7662 https://rfc-editor.org/rfc/rfc7662.html

    To prevent token scanning, RFC 7662 section 2.1 requires some form of
    authorization to call the endpoint, such as client authentication or a separate
    access token, and section 4 requires the caller to authenticate. The request
    must either authenticate a confidential client (HTTP Basic, client credentials
    in the body, or an RFC 7523 client assertion) or pass an OAuth2 Bearer Token
    which is allowed to access the scope `introspection`. On both paths the
    application involved (the authenticated client, or the client the token was
    issued to) must have ``can_introspect`` set, which it does unless an operator
    turned it off (section 4 recommends that callers be specifically authorized).
    """

    required_scopes = ["introspection"]
    form_encoded_endpoint = "The OAuth 2.0 token introspection endpoint (RFC 7662 section 2.1)"

    @staticmethod
    def application_can_introspect(application: object) -> bool:
        """Return whether *application* is authorized to introspect tokens (#1451).

        Anything but an application is refused. oauthlib serves request parameters
        as attributes of its request, so when a custom validator leaves
        ``request.client`` unset, a ``client`` parameter in the body or query string
        shows up there as a string.
        """
        return isinstance(application, AbstractApplication) and bool(application.can_introspect)

    def authenticate_client(self, request: HttpRequest) -> bool:
        """Authenticate the client and require it to be authorized to introspect.

        RFC 7662 section 4 requires the caller to authenticate, so only a
        confidential client counts: the validator accepts a public client without a
        secret on a device-code request, and that must not open this endpoint.

        The backend's own ``authenticate_client()`` decides whether the client
        authenticated, so a custom backend's policy always applies, and it runs once,
        so an RFC 7523 assertion's ``jti`` is consumed once. The client is the one
        ``OAuthLibCore.authenticate_client_request()`` recorded on *request* while it
        ran. A backend that reports success without recording one cannot say which
        client authenticated, so it is refused.

        A client that authenticates but is public or lacks ``can_introspect`` is
        treated as not authenticated, so the request falls through to the bearer-token
        path and is refused there unless it also carries an authorized access token.
        """
        core = self.get_oauthlib_core()
        # Overwrite whatever the request already carries, so only a client the
        # backend records during this call is ever read back.
        setattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE, _NOT_REPORTED)
        if not core.authenticate_client(request):
            return False
        client = getattr(request, _AUTHENTICATED_CLIENT_ATTRIBUTE, _NOT_REPORTED)
        if client is _NOT_REPORTED:
            # The backend authenticated the client without going through
            # OAuthLibCore.authenticate_client_request(), so that client cannot be
            # authorized: fail closed. The bearer-token path is unaffected.
            _warn_backend_once(type(core), _NOT_REPORTED_MESSAGE)
            return False
        if client is None:
            # The backend reported success although OAuthLibCore refused the client,
            # e.g. ``return super().authenticate_client(request) or other_check()``.
            # Nobody is authorized; warn so the deployer sees why.
            _warn_backend_once(type(core), _REFUSED_MESSAGE)
            return False
        if getattr(client, "client_type", None) != AbstractApplication.CLIENT_CONFIDENTIAL:
            log.debug(
                "Introspection refused: client %r did not authenticate as a confidential client",
                getattr(client, "client_id", None),
            )
            return False
        if not self.application_can_introspect(client):
            log.debug(
                "Introspection refused: client %r is not authorized to introspect tokens",
                getattr(client, "client_id", None),
            )
            return False
        return True

    def verify_request(self, request: HttpRequest) -> tuple[bool, OauthlibRequest | None]:
        """Verify the bearer token and require its client to be authorized to introspect.

        Besides the ``introspection`` scope, the application the token was issued to
        must have ``can_introspect``, so an operator who turns the flag off for a
        client refuses its tokens too. A token with no application is refused, since
        there is no client to check.
        """
        valid, oauthlib_request = super().verify_request(request)
        if not valid:
            return valid, oauthlib_request
        # The default validator sets request.access_token; a custom
        # validate_bearer_token() may set only request.client. oauthlib also exposes an
        # access_token *request parameter* under the same name, so only trust an object
        # that carries an application. A token without an application (hand-made, or
        # cached by RESOURCE_SERVER_INTROSPECTION_URL) is refused.
        access_token = getattr(oauthlib_request, "access_token", None)
        if hasattr(access_token, "application"):
            application = access_token.application
        else:
            application = getattr(oauthlib_request, "client", None)
        if not self.application_can_introspect(application):
            log.debug(
                "Introspection refused: the access token's client %r is not authorized to introspect tokens",
                getattr(application, "client_id", None),
            )
            # RFC 6750 section 3.1: the request requires higher privileges than
            # the access token provides. The description is a neutral one of our
            # own: oauthlib supplies none for this case (the missing-scope
            # description comes from our validator, not oauthlib), and it does not
            # name the can_introspect capability.
            oauthlib_request.oauth2_error = OrderedDict(
                [
                    ("error", "insufficient_scope"),
                    (
                        "error_description",
                        _("The access token is not authorized for token introspection."),
                    ),
                ]
            )
            return False, oauthlib_request
        return valid, oauthlib_request

    @staticmethod
    def get_token_response(token_value=None):
        if token_value is None:
            return JsonResponse(
                {"error": "invalid_request", "error_description": "Token parameter is missing."},
                status=400,
            )
        try:
            token_checksum = hashlib.sha256(token_value.encode("utf-8")).hexdigest()
            token = (
                get_access_token_model()
                .objects.select_related("user", "application")
                .get(token_checksum=token_checksum)
            )
        except ObjectDoesNotExist:
            return JsonResponse({"active": False}, status=200)
        else:
            if token.is_valid():
                data = {
                    "active": True,
                    "scope": token.scope,
                    "exp": int(calendar.timegm(token.expires.timetuple())),
                }
                if token.application:
                    data["client_id"] = token.application.client_id
                if token.user:
                    data["username"] = token.user.get_username()

                # RFC 8707: Include audience list if token has resource binding
                audiences = token.resource
                if audiences:
                    data["aud"] = audiences

                return JsonResponse(data)
            else:
                return JsonResponse({"active": False}, status=200)

    def get(self, request, *args, **kwargs):
        """
        Get the token from the URL parameters.
        URL: https://example.com/introspect?token=mF_9.B5f-4.1JqM

        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return self.get_token_response(request.GET.get("token", None))

    def post(self, request, *args, **kwargs):
        """
        Get the token from the body form parameters.
        Body: token=mF_9.B5f-4.1JqM

        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        return self.get_token_response(request.POST.get("token", None))
