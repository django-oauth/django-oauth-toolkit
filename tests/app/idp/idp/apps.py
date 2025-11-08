from corsheaders.signals import check_request_enabled
from django.apps import AppConfig


def cors_allow_origin(sender, request, **kwargs):
    origin = request.headers.get('Origin')

    return (
        request.path == "/o/userinfo/"
        or request.path == "/o/userinfo"
        or request.path == "/o/.well-known/openid-configuration"
        or request.path == "/o/.well-known/openid-configuration/"
        # this is for testing the device authorization flow in the example rp.
        # You would not normally have a browser-based client do this and shoudn't
        # open the following endpoints to CORS requests in a production environment.
        or (origin == 'http://localhost:5173' and request.path == "/o/device-authorization")
        or (origin == 'http://localhost:5173' and request.path == "/o/device-authorization/")
        or (origin == 'http://localhost:5173' and request.path == "/o/token")
        or (origin == 'http://localhost:5173' and request.path == "/o/token/")
    )


class IDPAppConfig(AppConfig):
    name = "idp"
    default = True

    def ready(self):
        check_request_enabled.connect(cors_allow_origin)
