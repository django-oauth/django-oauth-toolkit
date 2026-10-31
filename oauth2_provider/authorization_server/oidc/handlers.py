import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.signals import user_logged_out
from django.db import connections
from django.dispatch import receiver
from django.utils import timezone
from jwcrypto import jwt

from oauth2_provider.core import safe_fetch
from oauth2_provider.core.exceptions import BackchannelLogoutRequestError
from oauth2_provider.models import AbstractApplication, AbstractIDToken, get_id_token_model
from oauth2_provider.settings import oauth2_settings


logger = logging.getLogger(__name__)

# Set on the request by RPInitiatedLogoutView, which collects the targets before it
# deletes the tokens they are derived from and dispatches after the session is flushed.
# Without it the receiver would notify a second time whenever the tokens survive.
DISPATCHED_ATTR = "_dot_backchannel_logout_dispatched"


def get_logout_token_sub(id_token: AbstractIDToken) -> str:
    """The ``sub`` claim for a Logout Token: the one its ID Token was issued with.

    Back-Channel Logout 1.0 section 2.6 step 10 has the RP check the Logout Token's
    ``sub`` against the ID Token it holds, so the two must agree however a deployment
    customised ``sub``. The ID Token row records the value it was issued with, so this
    restates it rather than deriving it a second time.

    A row issued before the columns existed has neither ``sub`` nor ``iss`` recorded and
    falls back to the user's primary key, the default ``sub``. A newer row with an
    ``iss`` but no ``sub`` was issued without a ``sub`` that could be recorded: none at
    all, as when a validator removes it through ``get_claim_dict()``, or one longer than
    the 255 characters OpenID Connect allows. No substitute could match what the RP holds
    -- OpenID Connect Core 1.0 section 2 makes ``sub`` REQUIRED -- so nothing is sent.

    The one case this cannot tell apart: an ID Token issued with neither a recordable
    ``sub`` nor a recordable ``iss`` (over 2048 characters) looks like a pre-upgrade row,
    and its Logout Token carries the user's primary key.
    """
    if id_token.sub:
        return id_token.sub
    if id_token.iss:
        raise BackchannelLogoutRequestError(
            "The ID Token was issued without a sub that could be recorded (none, or over 255 "
            "characters), so no Logout Token can match it"
        )
    return str(id_token.user.pk)


def get_logout_token_iss(id_token: AbstractIDToken) -> str:
    """The ``iss`` claim for a Logout Token: the one its ID Token was issued with.

    Section 2.6 step 9 has the RP match it against the ID Token's ``iss``. Without
    ``OIDC_ISS_ENDPOINT`` that issuer was derived from the request that issued the token
    -- the RP's own token request, whose host need not be the one a browser logs out
    through -- so it is restated from the row rather than worked out again. A row issued
    before the column existed falls back to ``OIDC_ISS_ENDPOINT``, and without that there
    is nothing to name, so nothing is sent.
    """
    issuer = id_token.iss or oauth2_settings.OIDC_ISS_ENDPOINT
    if not issuer:
        raise BackchannelLogoutRequestError(
            "No issuer recorded on the ID Token, and OIDC_ISS_ENDPOINT is not set to fall back to"
        )
    return issuer


def send_backchannel_logout_request(id_token: AbstractIDToken, *args: Any, **kwargs: Any) -> None:
    """Send a logout token to the application's backchannel logout uri.

    The default ``OIDC_BACKCHANNEL_LOGOUT_HANDLER``: :func:`build_logout_token` and then
    :func:`post_logout_token`. A custom handler composes the same two.

    Raises :class:`BackchannelLogoutRequestError` and nothing else. Notifying a relying
    party is best-effort, and every caller -- the ``user_logged_out`` receiver among them
    -- has to be able to recover from a failure with a single except clause, so the whole
    body is wrapped rather than the delivery alone. That covers reaching the signing key,
    minting the JWT, the request itself, and dereferencing an ID Token whose nullable
    ``application`` or ``user`` is unset.
    """
    try:
        post_logout_token(
            id_token.application.backchannel_logout_uri,
            build_logout_token(id_token),
        )
    except BackchannelLogoutRequestError:
        raise
    except Exception as exc:
        raise BackchannelLogoutRequestError(str(exc)) from exc


def build_logout_token(id_token: AbstractIDToken, *, ttl: timedelta | None = None) -> str:
    """Mint the signed Logout Token (Back-Channel Logout 1.0 section 2.4) for *id_token*.

    Its ``iss`` and ``sub`` restate the ID Token's (:func:`get_logout_token_iss`,
    :func:`get_logout_token_sub`), which the relying party matches them against.

    Raises :class:`BackchannelLogoutRequestError` when there is nothing to send: the
    feature is off, no issuer or subject can be restated, or the application has no
    signing algorithm or no logout URI.
    """
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
        raise BackchannelLogoutRequestError("Backchannel logout not enabled")

    if id_token.application.algorithm == AbstractApplication.NO_ALGORITHM:
        raise BackchannelLogoutRequestError("Application must provide signing algorithm")

    if not id_token.application.backchannel_logout_uri:
        raise BackchannelLogoutRequestError("URL for backchannel logout not provided by client")

    ttl = ttl or timedelta(seconds=oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TOKEN_EXPIRE_SECONDS)

    issued_at = timezone.now()
    expiration_date = issued_at + ttl

    claims = {
        "iss": get_logout_token_iss(id_token),
        "sub": get_logout_token_sub(id_token),
        "aud": str(id_token.application.client_id),
        "iat": int(issued_at.timestamp()),
        "exp": int(expiration_date.timestamp()),
        # OpenID Connect Back-Channel Logout 1.0 section 2.4: the jti identifies this
        # Logout Token, not the ID Token that prompted it. RPs may reject a jti they
        # have already seen (section 2.6 step 8), so resending for the same ID Token
        # must not look like a replay.
        "jti": str(uuid.uuid4()),
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
    }

    # Standard JWT header
    header = {"typ": "logout+jwt", "alg": id_token.application.algorithm}

    # RS256 consumers expect a kid in the header for verifying the token
    if id_token.application.algorithm == AbstractApplication.RS256_ALGORITHM:
        header["kid"] = id_token.application.jwk_key.thumbprint()

    token = jwt.JWT(
        header=json.dumps(header, default=str),
        claims=json.dumps(claims, default=str),
    )

    token.make_signed_token(id_token.application.jwk_key)
    return token.serialize()


def post_logout_token(uri: str, logout_token: str, *, require_public_address: bool = True) -> None:
    """POST *logout_token* to *uri* (Back-Channel Logout 1.0 section 2.5).

    The URI is one a client registered, so the request goes through
    :func:`oauth2_provider.core.safe_fetch.post_form`: it refuses an address that is not
    public, connects to the address it validated, and holds the HTTP exchange to
    ``OIDC_BACKCHANNEL_LOGOUT_TIMEOUT`` however slowly the relying party answers; resolving
    the host before it is bounded by the system resolver's timeout.
    *require_public_address* exists for a local development setup that delivers to its
    own loopback interface, and turning it off takes code, not a setting.

    A redirect is a failure rather than something to follow: following would either drop
    the body (a 301, 302 or 303 turns the POST into a GET, which most endpoints answer
    200, so the failure would be silent) or repost the signed token to wherever
    ``Location`` names. Section 2.8 has the relying party answer 200 on success and 400
    on failure; any 2xx is taken as success. Raises
    :class:`BackchannelLogoutRequestError`.
    """
    status, headers = safe_fetch.post_form(
        uri,
        {"logout_token": logout_token},
        timeout=oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TIMEOUT,
        require_public_address=require_public_address,
        exc_class=BackchannelLogoutRequestError,
    )
    if 300 <= status < 400:
        raise BackchannelLogoutRequestError(
            "backchannel logout uri redirected to %r" % headers.get("Location")
        )
    if not 200 <= status < 300:
        raise BackchannelLogoutRequestError("backchannel logout uri answered HTTP %d" % status)


def collect_backchannel_logout_targets(
    user: AbstractBaseUser | None, *, initiating_application: AbstractApplication | None = None
) -> list[AbstractIDToken]:
    """One live ID Token per application to notify that ``user`` has logged out.

    *initiating_application* is the relying party that asked for the logout, which
    RP-Initiated Logout 1.0 section 2 says "is to be included in these notifications". It
    is known for certain to have had a session, so it is notified from its latest ID Token
    for the user even once that has expired; any other application needs a live one.

    Kept separate from delivery so a caller can read the rows *before* destroying them --
    RPInitiatedLogoutView deletes ID Tokens as part of logging out -- and so that
    dispatching touches no database at all, which is what makes the thread pool in
    :func:`send_backchannel_logout_requests` safe.

    ``application`` and ``user`` are selected eagerly for the same reason: the returned
    instances outlive their rows, and nothing in the dispatch path may lazy-load.

    Returns nothing when the feature is off. RPInitiatedLogoutView calls this on every
    logout, before it can know whether anything will be dispatched, so the guard belongs
    here rather than at the call site: a deployment that never enabled back-channel logout
    should not pay for a query per logout.
    """
    if user is None or not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
        return []

    id_tokens = (
        get_id_token_model()
        .objects.filter(user=user, application__isnull=False, expires__gt=timezone.now())
        .exclude(application__backchannel_logout_uri="")
        .select_related("application", "user")
        .order_by("application", "-expires")
    )

    targets = []
    seen = set()
    for id_token in id_tokens:
        if id_token.application_id in seen:
            continue
        seen.add(id_token.application_id)
        targets.append(id_token)

    if (
        initiating_application is not None
        and initiating_application.pk not in seen
        and initiating_application.backchannel_logout_uri
    ):
        latest = (
            get_id_token_model()
            .objects.filter(user=user, application=initiating_application)
            .select_related("application", "user")
            .order_by("-expires")
            .first()
        )
        if latest is not None:
            targets.append(latest)
    return targets


def send_backchannel_logout_requests(targets: list[AbstractIDToken]) -> None:
    """Deliver a logout token to each target. Never raises.

    Back-Channel Logout 1.0 section 2.3 encourages an OP to contact relying parties in
    parallel, so this fans out over ``OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS`` threads and
    the wall-clock cost is the slowest relying party of each round of that many, rather
    than the sum of all of them.

    The configured handler is user-supplied and so is anything it raises, and the
    settings read here can be wrong; a failure to notify must never prevent a logout, so
    nothing escapes. RPInitiatedLogoutView calls this after the user is already logged
    out, where an exception would turn a completed logout into a server error.
    """
    try:
        _send_backchannel_logout_requests(targets)
    except Exception as exc:
        logger.warning("Backchannel logout dispatch failed: %s", exc)


def _send_backchannel_logout_requests(targets: list[AbstractIDToken]) -> None:
    handler = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED or not callable(handler):
        return
    if not targets:
        return

    def dispatch(id_token: AbstractIDToken) -> None:
        try:
            handler(id_token=id_token)
        except Exception as exc:
            # Name the relying party, so an operator can tell which one keeps failing. The
            # stored URI is logged as it is: parsing it here could raise for a malformed one,
            # and nothing in this loop may, or the relying parties after it go un-notified.
            application = getattr(id_token, "application", None)
            logger.warning(
                "Backchannel logout notification to client %s at %s failed: %s",
                getattr(application, "client_id", None),
                getattr(application, "backchannel_logout_uri", None),
                exc,
            )

    def dispatch_on_worker(id_token: AbstractIDToken) -> None:
        # Django connections are thread-local and are closed in response to
        # ``request_finished``, which a pool worker never receives. The default handler
        # touches no database, but a custom one may, and a connection it opens here
        # would otherwise be held until the thread is collected -- one per worker per
        # logout, which a connection-limited server notices under logout load.
        try:
            dispatch(id_token)
        finally:
            connections.close_all()

    workers = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS
    if workers <= 1 or len(targets) == 1:
        # On the caller's own thread, where the connection belongs to the request and
        # closing it is not ours to do.
        for id_token in targets:
            dispatch(id_token)
        return

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        # list() so the context manager does not exit before every future has run.
        list(pool.map(dispatch_on_worker, targets))


@receiver(user_logged_out)
def on_user_logged_out_maybe_send_backchannel_logout(sender: type, **kwargs) -> None:
    # Nothing here may escape: django.contrib.auth.logout() sends this signal *before*
    # it flushes the session, and Signal.send() propagates, so an exception raised here
    # would leave the user logged in.
    try:
        if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
            return
        request = kwargs.get("request")
        if request is not None and getattr(request, DISPATCHED_ATTR, False):
            # RPInitiatedLogoutView has taken ownership of this logout: it snapshotted the
            # targets before deleting the tokens and dispatches once the session is gone.
            return
        # logout() sends user=None when the request was not authenticated. IDToken.user is
        # nullable, so filtering on None would match the user-less ID Tokens of unrelated
        # applications.
        send_backchannel_logout_requests(collect_backchannel_logout_targets(kwargs["user"]))
    except Exception as exc:  # collecting the targets, say, which runs outside dispatch's own guard
        logger.warning("Backchannel logout dispatch failed: %s", exc)
