import pytest
from django import VERSION


LOGIN_REQUIRED_MIDDLEWARE = "django.contrib.auth.middleware.LoginRequiredMiddleware"


@pytest.mark.skipif(VERSION < (5, 1), reason="LoginRequiredMiddleware was added in Django 5.1")
def test_login_required_middleware_is_installed(settings):
    """The suite runs behind LoginRequiredMiddleware on every Django that has it, so a provider
    view that forgets ``login_not_required`` fails the tests instead of a deployment."""
    assert LOGIN_REQUIRED_MIDDLEWARE in settings.MIDDLEWARE
