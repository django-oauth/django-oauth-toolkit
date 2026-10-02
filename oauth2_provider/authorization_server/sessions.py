"""When, and by which login, the end-user authenticated in the current browser session.

OpenID Connect ``max_age`` and ``prompt=login`` (Core 1.0 section 3.1.2.1)
are about the end-user's authentication *in this user agent*. ``last_login``
is shared by every session of the account, so a login in another browser
would make a stale session look fresh. Instead, each login is recorded in the
Django session that it authenticated: its time, and a random identifier that
tells one login from the next however close together they are.
"""

import time
import uuid
from typing import Any

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.http import HttpRequest


# Where the time (seconds since the epoch) and the identifier of the login that
# authenticated the Django session are kept. Django's login() flushes the
# session (another user) or cycles its key (the same user) before sending
# user_logged_in, and logout() flushes it, so both always belong to the current
# login.
AUTH_TIME_SESSION_KEY = "_oauth2_provider_auth_time"
AUTH_EVENT_SESSION_KEY = "_oauth2_provider_auth_event"


@receiver(user_logged_in, dispatch_uid="oauth2_provider.record_authentication_time")
def record_authentication_time(
    sender: type, request: HttpRequest | None, user: AbstractBaseUser, **kwargs: Any
) -> None:
    """Record the login in the session it authenticated."""
    if request is not None and hasattr(request, "session"):
        request.session[AUTH_TIME_SESSION_KEY] = time.time()
        request.session[AUTH_EVENT_SESSION_KEY] = uuid.uuid4().hex


def get_session_authentication_time(request: HttpRequest) -> float | None:
    """The time the current session was authenticated, or ``None`` if unknown.

    ``None`` for a session authenticated without :func:`django.contrib.auth.login`
    or before this was recorded.
    """
    session = getattr(request, "session", None)
    auth_time = session.get(AUTH_TIME_SESSION_KEY) if session is not None else None
    return auth_time if isinstance(auth_time, (int, float)) else None


def get_session_authentication_event(request: HttpRequest) -> str | None:
    """The identifier of the login that authenticated the current session, or
    ``None`` if unknown; it changes with every login.
    """
    session = getattr(request, "session", None)
    event = session.get(AUTH_EVENT_SESSION_KEY) if session is not None else None
    return event if isinstance(event, str) else None
