import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import requests
from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from jwcrypto import jwt

from oauth2_provider.core.exceptions import BackchannelLogoutRequestError
from oauth2_provider.models import AbstractApplication, get_id_token_model
from oauth2_provider.settings import oauth2_settings


logger = logging.getLogger(__name__)

# Set on the request by RPInitiatedLogoutView, which collects the targets before it
# deletes the tokens they are derived from and dispatches after the session is flushed.
# Without it the receiver would notify a second time whenever the tokens survive.
DISPATCHED_ATTR = "_dot_backchannel_logout_dispatched"


def get_logout_token_sub(id_token):
    """The ``sub`` claim for a Logout Token, via the configured OAuth2Validator.

    ID Tokens take ``sub`` from ``OAuth2Validator.get_claim_dict()``, which a deployment
    can override to emit something other than the user's primary key -- ``docs/oidc.rst``
    documents that as the supported way to change the claim. A Logout Token whose ``sub``
    disagrees with the ID Token's is rejected by an RP performing the check in
    Back-Channel Logout 1.0 section 2.6 step 10, and silently matches no session at an RP
    that skips it, so the two must be derived the same way.
    """
    return oauth2_settings.OAUTH2_VALIDATOR_CLASS().get_logout_token_sub(id_token)


def send_backchannel_logout_request(id_token, *args, **kwargs):
    """
    Send a logout token to the applications backchannel logout uri
    """

    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
        raise BackchannelLogoutRequestError("Backchannel logout not enabled")

    if id_token.application.algorithm == AbstractApplication.NO_ALGORITHM:
        raise BackchannelLogoutRequestError("Application must provide signing algorithm")

    if not id_token.application.backchannel_logout_uri:
        raise BackchannelLogoutRequestError("URL for backchannel logout not provided by client")

    if not oauth2_settings.OIDC_ISS_ENDPOINT:
        raise BackchannelLogoutRequestError("OIDC_ISS_ENDPOINT is not set")

    ttl = kwargs.get("ttl") or timedelta(seconds=oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TOKEN_EXPIRE_SECONDS)

    # Everything from here on -- signing key access, JWT minting, delivery -- is wrapped so
    # this function can only ever raise BackchannelLogoutRequestError. Notifying an RP is
    # best-effort, and callers (the user_logged_out receiver among them) must be able to
    # recover from a failure with a single except clause.
    try:
        issued_at = timezone.now()
        expiration_date = issued_at + ttl

        claims = {
            "iss": oauth2_settings.OIDC_ISS_ENDPOINT,
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

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"logout_token": token.serialize()}
        response = requests.post(
            id_token.application.backchannel_logout_uri,
            headers=headers,
            data=data,
            timeout=oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_TIMEOUT,
            # Section 2.5 specifies an HTTP POST carrying the token in the body. Following
            # a redirect would either drop that body (requests turns 301/302/303 into a
            # GET, which most RP endpoints answer 200, so the failure is silent) or repost
            # the signed token to whatever Location names.
            allow_redirects=False,
        )
        if response.is_redirect:
            raise BackchannelLogoutRequestError(
                "backchannel logout uri redirected to %r" % response.headers.get("Location")
            )
        response.raise_for_status()
    except BackchannelLogoutRequestError:
        raise
    except Exception as exc:
        raise BackchannelLogoutRequestError(str(exc)) from exc


def collect_backchannel_logout_targets(user):
    """One live ID Token per application to notify that ``user`` has logged out.

    Kept separate from delivery so a caller can read the rows *before* destroying them --
    RPInitiatedLogoutView deletes ID Tokens as part of logging out -- and so that
    dispatching touches no database at all, which is what makes the thread pool in
    :func:`send_backchannel_logout_requests` safe.

    ``application`` and ``user`` are selected eagerly for the same reason: the returned
    instances outlive their rows, and nothing in the dispatch path may lazy-load.
    """
    if user is None:
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
    return targets


def send_backchannel_logout_requests(targets):
    """Deliver a logout token to each target. Never raises.

    Back-Channel Logout 1.0 section 2.3 encourages an OP to contact relying parties in
    parallel, so this fans out over ``OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS`` threads and
    the wall-clock cost is the slowest relying party rather than the sum of all of them.

    The configured handler is user-supplied and so is anything it raises; a failure to
    notify must never prevent a logout.
    """
    handler = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED or not callable(handler):
        return
    if not targets:
        return

    def dispatch(id_token):
        try:
            handler(id_token=id_token)
        except Exception as exc:
            logger.warning("Backchannel logout notification failed: %s", exc)

    workers = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_MAX_WORKERS
    if workers <= 1 or len(targets) == 1:
        for id_token in targets:
            dispatch(id_token)
        return

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        # list() so the context manager does not exit before every future has run.
        list(pool.map(dispatch, targets))


@receiver(user_logged_out)
def on_user_logged_out_maybe_send_backchannel_logout(sender, **kwargs):
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
    except Exception as exc:  # pragma: no cover - defensive; dispatch already swallows
        logger.warning("Backchannel logout dispatch failed: %s", exc)
