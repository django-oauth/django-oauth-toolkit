"""Guard the settings the migration-check tox environments run under.

Issue #1453: those environments used to run under ``tests.mig_settings`` (and its
per-backend siblings), which installed ``oauth2_provider`` alone. The ``tests`` app
defines concrete models on top of every abstract model -- including the OIDC
``AbstractIDToken`` via ``LocalIDToken`` -- so altering an abstract model needs a
migration in ``tests/migrations`` too. Without the app installed,
``makemigrations --dry-run --check`` reported "No changes detected" while
``tests/migrations`` was stale, and the documented workflow generated only half of
the migrations a model change requires.
"""

import configparser
import importlib
import re
from pathlib import Path

import pytest


TOX_INI = Path(__file__).resolve().parent.parent / "tox.ini"

# The envs whose whole job is to detect missing migrations. `.migrations-base` holds
# the shared commands and declares no settings module of its own.
MIGRATION_ENV = re.compile(r"^testenv:(migrations-|scenario-migrate-)")


def _migration_env_settings():
    """Map each migration-check tox env to the settings module it runs under."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(TOX_INI)
    found = {}
    for section in parser.sections():
        if not MIGRATION_ENV.match(section):
            continue
        for line in parser[section].get("setenv", "").splitlines():
            name, sep, value = line.partition("=")
            if sep and name.strip() == "DJANGO_SETTINGS_MODULE":
                found[section] = value.strip()
    return found


def test_migration_envs_are_discoverable():
    """A tox.ini rename must not quietly empty out the parametrization below."""
    assert _migration_env_settings(), f"no migration-check envs found in {TOX_INI}"


@pytest.mark.parametrize(("env", "settings_module"), sorted(_migration_env_settings().items()))
def test_migration_env_settings_install_every_migrated_app(env, settings_module):
    try:
        module = importlib.import_module(settings_module)
    except ModuleNotFoundError as exc:  # pragma: no cover - backend driver absent
        pytest.skip(f"{settings_module} requires {exc.name}, which this cell does not install")

    for app in ("oauth2_provider", "tests"):
        assert app in module.INSTALLED_APPS, (
            f"tox env {env} checks for missing migrations under {settings_module}, which does not "
            f"install {app!r}; missing {app} migrations would go undetected (issue #1453)"
        )
