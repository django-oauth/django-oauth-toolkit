from typing import Any
from urllib.parse import parse_qs, urlsplit

from django.contrib.auth.views import LoginView

from oauth2_provider.models import AbstractApplication, get_application_model


class ClientBrandedLoginView(LoginView):
    """Django's login view, showing the client's registered logo and links.

    When the login was started from the authorization endpoint, ``next`` carries
    the authorization request, so its ``client_id`` names the client the End-User
    is about to approve. Showing that client's ``logo_uri``, ``client_uri``,
    ``policy_uri`` and ``tos_uri`` here (RFC 7591 section 2) is what the OpenID
    certification review modules ``oidcc-registration-logo-uri``,
    ``oidcc-registration-policy-uri`` and ``oidcc-registration-tos-uri``
    screenshot.
    """

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["application"] = self.get_client_application()
        return context

    def get_client_application(self) -> AbstractApplication | None:
        # get_redirect_url() returns "next" only when it passes Django's
        # safe-URL check, so a foreign URL never selects an application.
        client_ids = parse_qs(urlsplit(self.get_redirect_url()).query).get("client_id")
        if not client_ids:
            return None
        return get_application_model().objects.filter(client_id=client_ids[0]).first()
