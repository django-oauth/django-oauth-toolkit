from corsheaders.signals import check_request_enabled
from django.apps import AppConfig


def cors_allow_origin(sender, request, **kwargs):
    origin = request.headers.get("Origin")

    # django-oauth-toolkit CORS-enables the OIDC discovery, JWKS and userinfo responses
    # itself, so none of them need an entry here. The one exception is the userinfo
    # preflight: django-cors-headers answers every OPTIONS preflight from middleware,
    # before any view runs, so the toolkit's own OPTIONS handler never sees it. An IdP
    # that does not install django-cors-headers needs nothing at all for userinfo.
    if request.method == "OPTIONS" and request.path.rstrip("/") == "/o/userinfo":
        return True

    return (
        # this is for testing the device authorization flow in the example rp.
        # You would not normally have a browser-based client do this and shouldn't
        # open the following endpoints to CORS requests in a production environment.
        (origin == "http://localhost:5173" and request.path == "/o/device-authorization")
        or (origin == "http://localhost:5173" and request.path == "/o/device-authorization/")
        or (origin == "http://localhost:5173" and request.path == "/o/token")
        or (origin == "http://localhost:5173" and request.path == "/o/token/")
    )


class IDPAppConfig(AppConfig):
    name = "idp"
    default = True

    def ready(self):
        check_request_enabled.connect(cors_allow_origin)
