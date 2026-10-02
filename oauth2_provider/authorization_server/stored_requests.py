"""Stored authorization requests — validated requests referenced by a single-use ``request_uri``.

The authorization server keeps an authorization request on the server and gives
out a reference to it, a ``request_uri`` in the ``urn:ietf:params:oauth:request_uri:``
namespace (:rfc:`9126#section-2.2`). The authorization endpoint is then called with
only ``client_id`` and that ``request_uri``, so the request itself never enters the
browser URL. Each reference is bound to one client and can be used only once
(:rfc:`9126#section-4`).

Contract for producers
----------------------

Every caller of :func:`store_authorization_request` MUST store only an authorization
request that has already been validated in full for the bound ``client_id``:

* it passed the authorization-request validation the authorization endpoint runs
  (``validate_authorization_request``, i.e. oauthlib and ``OAuth2Validator``);
* it passed the checks the authorization endpoint makes itself because oauthlib
  does not: ``prompt`` is not repeated and, for an OpenID Connect request,
  ``max_age`` is neither repeated nor malformed;
* it carries no ``request`` or ``request_uri`` parameter, and no
  client-authentication parameter (``client_secret``, ``client_assertion``,
  ``client_assertion_type``);
* its parameters map each name to its last value, except ``resource``
  (:rfc:`8707`), which maps to the list of its values.

The authorization endpoint relies on this. It treats a stored request as
authoritative: parameters sent alongside the ``request_uri`` are ignored, and while
the end-user is still anonymous the request is only a reference, so the early
``prompt`` / ``max_age`` checks are not repeated for it. A producer that stored an
unvalidated request would bypass those checks. The rule applies to every producer,
present and future.

Current producers:

* the pushed authorization request endpoint
  (:class:`oauth2_provider.authorization_server.views.par.PushedAuthorizationRequestView`,
  :rfc:`9126`);
* the authorization endpoint, when it sends the user to log in partway through a
  stored request: the parameters it re-stores were themselves resolved from this
  store (:meth:`oauth2_provider.authorization_server.views.base.AuthorizationView._redirect_to_login`);
* the authorization endpoint, for an OpenID Connect request object once it has
  assembled and validated the request
  (:meth:`oauth2_provider.authorization_server.views.base.AuthorizationView._store_resolved_request`).
"""

import secrets
from typing import Optional

from django.db import transaction

from oauth2_provider.models import create_stored_authorization_request, get_stored_authorization_request_model


# Request URIs use the IANA-registered URN sub-namespace (RFC 9126 §2.2 / §9.3).
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


class StoredAuthorizationRequestError(Exception):
    """A stored authorization request could not be resolved or consumed.

    Carries an OAuth ``error`` code and human-readable ``description`` for the
    view layer to render as a non-redirecting authorization error.
    """

    def __init__(self, description: str, error: str = "invalid_request") -> None:
        super().__init__(description)
        self.error = error
        self.description = description


def is_stored_request_uri(value: Optional[str]) -> bool:
    """Whether ``value`` is in the namespace of request URIs this store issues.

    This checks the form only, not that a stored request exists for it.
    """
    return bool(value) and value.startswith(REQUEST_URI_PREFIX)


def store_authorization_request(client_id: str, parameters: dict, *, expires_in: int) -> str:
    """Persist a validated authorization request and return its ``request_uri``.

    The caller MUST have validated the request in full first; see the module
    docstring for the contract. The ``request_uri`` is bound to ``client_id``,
    expires after ``expires_in`` seconds, and contains a cryptographically strong
    random component so it is infeasible to guess (RFC 9126 §2.2 / §7.1).
    """
    request_uri = REQUEST_URI_PREFIX + secrets.token_urlsafe(32)
    create_stored_authorization_request(
        request_uri=request_uri,
        client_id=client_id,
        parameters=parameters,
        expires_in=expires_in,
    )
    return request_uri


def consume_authorization_request(request_uri: str, client_id: Optional[str]) -> dict:
    """Atomically consume a ``request_uri`` and return its stored parameters.

    One-time use (RFC 9126 §4 / §7.3): the record is read and deleted under a row
    lock in a single transaction, so two concurrent authorization requests cannot
    both consume the same ``request_uri``. The client binding (RFC 9126 §2.2) is
    verified *before* deletion, so a party that merely obtained a leaked
    ``request_uri`` — and is not the bound client — cannot consume/invalidate it.

    Raises :class:`StoredAuthorizationRequestError` when the ``request_uri`` is
    unknown or already used, is not bound to ``client_id``, or has expired.
    """
    stored_request_model = get_stored_authorization_request_model()
    try:
        with transaction.atomic():
            record = stored_request_model.objects.select_for_update().get(request_uri=request_uri)
            if not client_id or client_id != record.client_id:
                # Leave the record intact so the legitimate client can still use it.
                raise StoredAuthorizationRequestError("The request_uri was not issued to this client.")
            parameters = record.parameters
            expired = record.is_expired()
            record.delete()
    except stored_request_model.DoesNotExist:
        raise StoredAuthorizationRequestError("The request_uri is invalid or has already been used.")
    if expired:
        raise StoredAuthorizationRequestError("The request_uri has expired.")
    return parameters
