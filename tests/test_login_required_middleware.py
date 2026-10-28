LOGIN_REQUIRED_MIDDLEWARE = "django.contrib.auth.middleware.LoginRequiredMiddleware"


def test_login_required_middleware_is_installed(settings):
    """The suite runs behind LoginRequiredMiddleware, so a provider view that forgets
    ``login_not_required`` fails the tests instead of a deployment."""
    assert LOGIN_REQUIRED_MIDDLEWARE in settings.MIDDLEWARE
