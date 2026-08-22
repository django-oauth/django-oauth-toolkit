from oauth2_provider.authorization_server.forms import ApplicationForm
from oauth2_provider.authorization_server.views.application import APPLICATION_FIELDS


class SampleApplicationForm(ApplicationForm):
    """Application form exposing the extra field of ``tests.SampleApplication``."""

    class Meta:
        fields = APPLICATION_FIELDS + ("custom_field",)


class ExcludeApplicationForm(ApplicationForm):
    """Application form that picks its fields with ``Meta.exclude`` instead."""

    class Meta:
        # client_jwks_uri only to keep Django's URLField default-scheme deprecation
        # warning out of the test run; the rest is what such a form would exclude.
        exclude = ("user", "skip_authorization", "custom_field", "client_jwks_uri")
