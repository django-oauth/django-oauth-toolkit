"""RFC 9126 Pushed Authorization Requests — Authorization Server business logic.

The HTTP surface lives in :mod:`oauth2_provider.authorization_server.views` (the PAR
endpoint and the authorization endpoint's PAR enforcement); this module holds the
business logic they delegate to, independent of the view/response layer. Pushed
requests are kept in the generic store in
:mod:`oauth2_provider.authorization_server.stored_requests`.
"""

from typing import TYPE_CHECKING, Optional

from django.http import HttpRequest
from oauthlib.common import Request as OAuthlibRequest

from oauth2_provider.models import AbstractApplication, get_application_model
from oauth2_provider.settings import oauth2_settings


if TYPE_CHECKING:
    from oauth2_provider.core.backends_oauthlib import OAuthLibCore


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
    :meth:`oauth2_provider.core.backends_oauthlib.OAuthLibCore.extract_body`. Repeated
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
    return (
        get_application_model()
        .objects.filter(client_id=client_id, require_pushed_authorization_requests=True)
        .exists()
    )
