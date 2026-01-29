from django.apps import AppConfig


class DOTConfig(AppConfig):
    name = "oauth2_provider"
    verbose_name = "Django OAuth Toolkit"

    def ready(self):
        # Import checks to ensure they run.
        from . import checks  # noqa: F401
