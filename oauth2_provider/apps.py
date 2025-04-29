from django.apps import AppConfig


class DOTConfig(AppConfig):
    name = "oauth2_provider"
    verbose_name = "Django OAuth Toolkit"

    def ready(self):
        # Connect the receiver that records when each session was authenticated.
        from .authorization_server import sessions  # noqa: F401

        # Import checks to ensure they run, and handlers to connect its receivers.
        from .authorization_server.oidc import handlers  # noqa: F401
        from .core import checks  # noqa: F401
