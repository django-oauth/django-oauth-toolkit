"""
The `compat` module provides support for backwards compatibility with older
versions of Django and Python.
"""

try:
    # Django 5.1 introduced LoginRequiredMiddleware, and login_not_required decorator
    from django.contrib.auth.decorators import login_not_required
except ImportError:

    def login_not_required(view_func):
        return view_func


__all__ = ["login_not_required"]
