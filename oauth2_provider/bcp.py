"""
Helpers for the RFC 9700 (OAuth 2.0 Security Best Current Practice) gates.

Each ``COMPLIANT_BCP_RFC9700_*`` setting covers one RFC 9700 recommendation. When the
gate is ``True`` the compliant behavior is always enforced (the insecure request is
rejected, or the secure action is performed instead). How the non-compliant state is
*surfaced* while the gate is ``False`` depends on the kind of gate:

* **Request-time gates** — a discrete, client-triggered insecure action (the implicit
  grant, the password grant, a ``plain`` PKCE challenge, an access token in the query
  string). These call :func:`bcp_compliant` on the discouraged code path, which emits
  a ``DeprecationWarning`` (and a log line) each time the action is exercised while
  the gate is not yet enforced.
* **Ambient/config gates** — a server-wide posture that would otherwise be exercised on
  *every* request (storing tokens in plaintext, omitting the RFC 9207 ``iss``
  parameter). Emitting a warning per operation would flood logs, so these are surfaced
  once, at configuration time, by the ``--deploy`` system checks in
  :mod:`oauth2_provider.checks` (``W005``/``W006``) rather than per operation.

The gates default to ``False`` (legacy behavior preserved) and are scheduled to flip
to ``True`` in the 4.0 release.
"""

import logging
import warnings

from .settings import oauth2_settings


log = logging.getLogger("oauth2_provider")


def bcp_warning_message(setting_name, behavior):
    """Build the standard warning/enforcement message for a gate."""
    setting_ref = f'OAUTH2_PROVIDER["{setting_name}"]'
    return (
        f"{behavior} is discouraged by RFC 9700 (OAuth 2.0 Security Best Current "
        f"Practice). It is currently allowed because {setting_ref} is False; this "
        f"default is scheduled to change to True in django-oauth-toolkit 4.0. Set "
        f"{setting_ref} to True to adopt the compliant behavior now."
    )


def bcp_compliant(setting_name, behavior):
    """
    Return whether the RFC 9700 recommendation covered by ``setting_name`` is
    enforced (the gate is ``True``).

    Call this only on the discouraged code path (i.e. when the non-compliant
    behavior is actually being requested). While the gate is ``False`` a
    ``DeprecationWarning`` (and a log line) is emitted, nagging toward compliance.
    The caller is expected to reject the discouraged request when this returns
    ``True``.

    :param setting_name: name of the ``COMPLIANT_BCP_RFC9700_*`` setting.
    :param behavior: human-readable description of the discouraged behavior, used in
        the warning message.
    :return: ``True`` if the compliant behavior must be enforced, ``False`` if the
        legacy behavior may proceed.
    """
    compliant = getattr(oauth2_settings, setting_name)
    if not compliant:
        message = bcp_warning_message(setting_name, behavior)
        warnings.warn(message, DeprecationWarning, stacklevel=2)
        log.warning(message)
    return compliant
