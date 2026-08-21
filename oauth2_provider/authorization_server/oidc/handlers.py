import json
import logging
import uuid
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

OFFLINE_ACCESS_SCOPE = "offline_access"


def send_backchannel_logout_request(id_token, *args, **kwargs):
    """
    Send a logout token to the applications backchannel logout uri
    """

    ttl = kwargs.get("ttl") or timedelta(minutes=10)

    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
        raise BackchannelLogoutRequestError("Backchannel logout not enabled")

    if id_token.application.algorithm == AbstractApplication.NO_ALGORITHM:
        raise BackchannelLogoutRequestError("Application must provide signing algorithm")

    if not id_token.application.backchannel_logout_uri:
        raise BackchannelLogoutRequestError("URL for backchannel logout not provided by client")

    if not oauth2_settings.OIDC_ISS_ENDPOINT:
        raise BackchannelLogoutRequestError("OIDC_ISS_ENDPOINT is not set")

    # Everything from here on -- signing key access, JWT minting, delivery -- is wrapped so
    # this function can only ever raise BackchannelLogoutRequestError. Notifying an RP is
    # best-effort, and callers (the user_logged_out receiver among them) must be able to
    # recover from a failure with a single except clause.
    try:
        issued_at = timezone.now()
        expiration_date = issued_at + ttl

        claims = {
            "iss": oauth2_settings.OIDC_ISS_ENDPOINT,
            "sub": str(id_token.user.pk),
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
        )
        response.raise_for_status()
    except Exception as exc:
        raise BackchannelLogoutRequestError(str(exc)) from exc


@receiver(user_logged_out)
def on_user_logged_out_maybe_send_backchannel_logout(sender, **kwargs):
    handler = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED or not callable(handler):
        return

    # django.contrib.auth.logout() sends this signal with user=None when the request was
    # not authenticated. IDToken.user is nullable, so filtering on None would match the
    # user-less ID Tokens of unrelated applications.
    user = kwargs["user"]
    if user is None:
        return

    # ID tokens for this user whose application registered a backchannel logout uri. Only
    # live ones: an expired ID Token is the closest available signal that the RP is no
    # longer participating (see the note in docs/oidc.rst).
    id_tokens = (
        get_id_token_model()
        .objects.filter(user=user, application__isnull=False, expires__gt=timezone.now())
        .exclude(application__backchannel_logout_uri="")
        .select_related("application")
        .order_by("application", "-expires")
    )

    # Group by application and send one request per application
    applications_notified = set()
    for id_token in id_tokens:
        # Sessions holding offline_access persist beyond logout. Checked here rather than
        # in the query because scope is a space-separated list of case-sensitive values,
        # which no database lookup matches exactly.
        if OFFLINE_ACCESS_SCOPE in id_token.scope.split():
            continue
        if id_token.application in applications_notified:
            continue
        applications_notified.add(id_token.application)
        try:
            handler(id_token=id_token)
        except Exception as exc:
            # Logging a user out must not depend on any RP being reachable, and the
            # handler is user-supplied, so nothing it raises may escape.
            logger.warning("Backchannel logout notification failed: %s", exc)
