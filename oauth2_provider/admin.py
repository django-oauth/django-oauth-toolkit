"""Backward-compatible import shim.

``oauth2_provider.admin`` has moved to
``oauth2_provider.authorization_server.admin``.

This shim re-exports the moved module without a DeprecationWarning, because
Django's admin autodiscovery imports ``oauth2_provider.admin`` at startup. The
old path is deprecated and will be removed in django-oauth-toolkit 4.0.

The moved module resolves the ``*_ADMIN_CLASS`` settings while it is being
imported, which imports the project's own admin module. If that module imports
from this old path (``from oauth2_provider.admin import ApplicationAdmin``), it
finds this shim still initializing -- the ``sys.modules`` alias below has not
been installed yet -- so the module-level ``__getattr__`` forwards the lookup to
the moved module, whose classes are already defined by then. Once the alias is
installed the shim object is unreachable and ``__getattr__`` is never consulted
again.
"""

import sys
from typing import Any


def __getattr__(name: str) -> Any:
    moved = sys.modules.get("oauth2_provider.authorization_server.admin")
    if moved is None:
        raise AttributeError(name)
    return getattr(moved, name)


from oauth2_provider.authorization_server import admin as _moved  # noqa: E402


sys.modules[__name__] = _moved
