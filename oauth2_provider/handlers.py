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


def send_backchannel_logout_request(id_token, *args, **kwargs):
    """
    Send a logout token to the applications backchannel logout uri
    """

    ttl = kwargs.get("ttl") or timedelta(minutes=10)

    try:
        assert oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED, "Backchannel logout not enabled"
        assert id_token.application.algorithm != AbstractApplication.NO_ALGORITHM, (
            "Application must provide signing algorithm"
        )
        assert id_token.application.backchannel_logout_uri is not None, (
            "URL for backchannel logout not provided by client"
        )

        issued_at = timezone.now()
        expiration_date = issued_at + ttl

        claims = {
            "iss": oauth2_settings.OIDC_ISS_ENDPOINT,
            "sub": str(id_token.user.id),
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
        response = requests.post(id_token.application.backchannel_logout_uri, headers=headers, data=data)
        response.raise_for_status()
    except (AssertionError, requests.RequestException) as exc:
        raise BackchannelLogoutRequestError(str(exc))


@receiver(user_logged_out)
def on_user_logged_out_maybe_send_backchannel_logout(sender, **kwargs):
    handler = oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_HANDLER
    if not oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED or not callable(handler):
        return

    user = kwargs["user"]
    id_tokens = IDToken.objects.filter(application__backchannel_logout_uri__isnull=False, user=user)
    for id_token in id_tokens:
        try:
            handler(id_token=id_token)
        except BackchannelLogoutRequestError as exc:
            logger.warn(str(exc))
