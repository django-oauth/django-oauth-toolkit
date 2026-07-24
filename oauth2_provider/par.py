"""RFC 9126 Pushed Authorization Requests — Authorization Server business logic.

The HTTP surface lives in :mod:`oauth2_provider.views` (the PAR endpoint and the
authorization endpoint's ``request_uri`` handling); this module holds the
business logic they delegate to, independent of the view/response layer.
"""

import secrets
from typing import TYPE_CHECKING, Optional

from django.db import transaction
from django.http import HttpRequest
from oauthlib.common import Request as OAuthlibRequest

from .models import (
    AbstractApplication,
    create_pushed_authorization_request,
    get_application_model,
    get_par_request_model,
)
from .settings import oauth2_settings


if TYPE_CHECKING:
    from .oauth2_backends import OAuthLibCore


# Request URIs use the IANA-registered URN sub-namespace (RFC 9126 §2.2 / §9.3).
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

# Parameters that authenticate the client at a token-style endpoint. They are
# relied upon only for client authentication and are not part of the authorization
# request itself (RFC 9126 §2.1), so they are never stored on the pushed request.
CLIENT_AUTH_PARAMETERS = frozenset(
    {
        "client_secret",
        "client_assertion",
        "client_assertion_type",
    }
)


class PushedAuthorizationError(Exception):
    """A pushed authorization request could not be resolved or consumed.

    Carries an OAuth ``error`` code and human-readable ``description`` for the
    view layer to render — as a token-style JSON error at the PAR endpoint, or a
    non-redirecting authorization error at the authorization endpoint.
    """

    def __init__(self, description: str, error: str = "invalid_request") -> None:
        super().__init__(description)
        self.error = error
        self.description = description


def authenticate_par_client(core: "OAuthLibCore", request: HttpRequest) -> Optional[AbstractApplication]:
    """Authenticate the PAR request's client, returning the client or ``None``.

    Confidential clients are authenticated with their credentials; public clients
    that cannot authenticate are accepted on ``client_id`` alone, mirroring how the
    authorization-code grant treats public clients.
    """
    uri, http_method, body, headers = core._extract_params(request)
    oauthlib_request = OAuthlibRequest(uri, http_method=http_method, body=body, headers=headers)
    validator = core.server.request_validator

    if validator.authenticate_client(oauthlib_request):
        return oauthlib_request.client

    client_id = oauthlib_request.client_id
    if client_id and validator.authenticate_client_id(client_id, oauthlib_request):
        return oauthlib_request.client

    return None


def effective_client_id(request: HttpRequest) -> Optional[str]:
    """The ``client_id`` oauthlib validates against: body wins over the query string.

    oauthlib merges the request URI (query string) and body, so a client_id in
    either place is honored during validation; the binding check must consider both.
    """
    return request.POST.get("client_id") or request.GET.get("client_id")


def collect_pushed_parameters(request: HttpRequest) -> dict:
    """Build the JSON-serialisable mapping of authorization-request parameters to
    store, dropping client-authentication parameters.

    The query string and body are merged so the stored parameters reflect exactly
    what oauthlib validated (it merges the request URI and body). The body wins on
    conflicts — applied last, matching oauthlib and
    :meth:`oauth2_provider.oauth2_backends.OAuthLibCore.extract_body`. Repeated
    ``resource`` values (RFC 8707) are preserved as a list; all other parameters
    keep their last value.
    """
    parameters = {}
    resource_values = []
    for source in (request.GET, request.POST):
        for key in source:
            if key in CLIENT_AUTH_PARAMETERS:
                continue
            values = source.getlist(key)
            if key == "resource":
                resource_values.extend(values)
            else:
                parameters[key] = values[-1]
    if resource_values:
        parameters["resource"] = resource_values
    return parameters


def store_pushed_request(client_id: str, parameters: dict) -> tuple[str, int]:
    """Persist a pushed authorization request and return ``(request_uri, expires_in)``.

    The ``request_uri`` contains a cryptographically strong random component so it
    is infeasible to guess (RFC 9126 §2.2 / §7.1).
    """
    request_uri = REQUEST_URI_PREFIX + secrets.token_urlsafe(32)
    expires_in = oauth2_settings.PAR_REQUEST_URI_LIFETIME_SECONDS
    create_pushed_authorization_request(
        request_uri=request_uri,
        client_id=client_id,
        parameters=parameters,
        expires_in=expires_in,
    )
    return request_uri, expires_in


def pushed_authorization_required(client_id: Optional[str]) -> bool:
    """Whether an authorization request for ``client_id`` must go through PAR.

    True when the server-wide setting requires PAR, or when the client's
    ``require_pushed_authorization_requests`` flag is set (RFC 9126 §4 / §6). The
    server-wide setting is a floor; a per-client value never relaxes it.
    """
    if oauth2_settings.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS:
        return True
    if not client_id:
        return False
    application = get_application_model().objects.filter(client_id=client_id).first()
    return bool(application and application.require_pushed_authorization_requests)


def consume_pushed_request(request_uri: str, client_id: Optional[str]) -> dict:
    """Atomically consume a ``request_uri`` and return its stored parameters.

    One-time use (RFC 9126 §4 / §7.3): the record is read and deleted under a row
    lock in a single transaction, so two concurrent authorization requests cannot
    both consume the same ``request_uri``. The client binding (RFC 9126 §2.2) is
    verified *before* deletion, so a party that merely obtained a leaked
    ``request_uri`` — and is not the bound client — cannot consume/invalidate it.

    Raises :class:`PushedAuthorizationError` when the ``request_uri`` is unknown or
    already used, is not bound to ``client_id``, or has expired.
    """
    par_model = get_par_request_model()
    try:
        with transaction.atomic():
            record = par_model.objects.select_for_update().get(request_uri=request_uri)
            if not client_id or client_id != record.client_id:
                # Leave the record intact so the legitimate client can still use it.
                raise PushedAuthorizationError("The request_uri was not issued to this client.")
            parameters = record.parameters
            expired = record.is_expired()
            record.delete()
    except par_model.DoesNotExist:
        raise PushedAuthorizationError("The request_uri is invalid or has already been used.")
    if expired:
        raise PushedAuthorizationError("The request_uri has expired.")
    return parameters
