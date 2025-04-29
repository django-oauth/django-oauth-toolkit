import json
import logging
from datetime import timedelta

import requests
from django.contrib.auth.signals import user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from jwcrypto import jwt

from .exceptions import BackchannelLogoutRequestError
from .models import AbstractApplication, get_id_token_model
from .settings import oauth2_settings


IDToken = get_id_token_model()

logger = logging.getLogger(__name__)

BACKCHANNEL_LOGOUT_TIMEOUT = getattr(oauth2_settings, "OIDC_BACKCHANNEL_LOGOUT_TIMEOUT", 5)


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

    try:
        issued_at = timezone.now()
        expiration_date = issued_at + ttl

        claims = {
            "iss": oauth2_settings.OIDC_ISS_ENDPOINT,
            "sub": str(id_token.user.pk),
            "aud": str(id_token.application.client_id),
            "iat": int(issued_at.timestamp()),
            "exp": int(expiration_date.timestamp()),
            "jti": id_token.jti,
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
            timeout=BACKCHANNEL_LOGOUT_TIMEOUT,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise BackchannelLogoutRequestError(str(exc))


@receiver(user_logged_out)
def on_user_logged_out_maybe_send_backchannel_logout(sender, **kwargs):
    handler = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED or not callable(handler):
        return

    now = timezone.now()
    user = kwargs["user"]

    # Get ID tokens for user where Application has backchannel_logout_uri configured
    # and scope doesn't contain offline_access (those sessions persist beyond logout)
    id_tokens = (
        IDToken.objects.filter(user=user, application__backchannel_logout_uri__isnull=False, expires__gt=now)
        .exclude(scope__icontains="offline_access")
        .exclude(application__backchannel_logout_uri="")
        .select_related("application")
        .order_by("application", "-expires")
    )

    # Group by application and send one request per application
    applications_notified = set()
    for id_token in id_tokens:
        if id_token.application not in applications_notified:
            applications_notified.add(id_token.application)
            try:
                handler(id_token=id_token)
            except BackchannelLogoutRequestError as exc:
                logger.warning(str(exc))
