"""
Tests for the ``cleardcrapplications`` management command.
"""

import json
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.urls import reverse
from django.utils import timezone

from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_id_token_model,
    get_refresh_token_model,
)

from . import presets
from .common_testing import OAuth2ProviderTestCase as TestCase


UserModel = get_user_model()
Application = get_application_model()


def _dcr_app(name, *, source=None, created_delta=timedelta(days=-30)):
    app = Application.objects.create(
        name=name,
        client_type=Application.CLIENT_PUBLIC,
        authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        redirect_uris="https://client.example.com/callback",
        registration_source=source or Application.RegistrationSource.DCR,
    )
    # ``created`` is auto_now_add, so age it explicitly with an update that
    # bypasses the auto field.
    Application.objects.filter(pk=app.pk).update(created=timezone.now() + created_delta)
    app.refresh_from_db()
    return app


# batch_size=1 exercises the batched-transaction loop across prune and survive
# outcomes; None exercises the default.
@pytest.mark.parametrize("batch_size", [None, 1])
@pytest.mark.django_db(databases="__all__")
def test_cleardcrapplications_prunes_only_dead_aged_dcr_rows(django_user_model, capsys, batch_size):
    user = django_user_model.objects.create_user("dcr-prune-user")
    now = timezone.now()

    dead = _dcr_app("dead.example.com")
    dead_tokens = _dcr_app("dead-tokens.example.com")
    get_access_token_model().objects.create(
        token="expired-at", expires=now - timedelta(hours=1), application=dead_tokens
    )
    get_refresh_token_model().objects.create(
        token="revoked-rt", user=user, application=dead_tokens, revoked=now - timedelta(hours=1)
    )

    # Survivors: too young, not DCR, or holding a live token/grant.
    young = _dcr_app("young.example.com", created_delta=timedelta(days=-1))
    manual = _dcr_app("manual.example.com", source=Application.RegistrationSource.MANUAL)
    cimd = _dcr_app("cimd.example.com", source=Application.RegistrationSource.CIMD)
    live_access = _dcr_app("live-access.example.com")
    get_access_token_model().objects.create(
        token="live-at", expires=now + timedelta(hours=1), application=live_access
    )
    live_refresh = _dcr_app("live-refresh.example.com")
    get_refresh_token_model().objects.create(token="live-rt", user=user, application=live_refresh)
    live_grant = _dcr_app("live-grant.example.com")
    get_grant_model().objects.create(
        user=user,
        code="live-code",
        application=live_grant,
        expires=now + timedelta(minutes=5),
        redirect_uri="https://client.example.com/callback",
    )
    live_idtoken = _dcr_app("live-idtoken.example.com")
    get_id_token_model().objects.create(expires=now + timedelta(hours=1), application=live_idtoken)

    call_command("cleardcrapplications", **({} if batch_size is None else {"batch_size": batch_size}))

    survivors = set(Application.objects.values_list("pk", flat=True))
    assert survivors == {
        young.pk,
        manual.pk,
        cimd.pk,
        live_access.pk,
        live_refresh.pk,
        live_grant.pk,
        live_idtoken.pk,
    }
    assert dead.pk not in survivors and dead_tokens.pk not in survivors
    assert "Deleted 2 orphaned DCR application(s)" in capsys.readouterr().out


@pytest.mark.django_db(databases="__all__")
def test_cleardcrapplications_min_age_days_zero_prunes_fresh_rows(capsys):
    # With --min-age-days=0 the age grace period is disabled, so even a
    # just-registered tokenless DCR app is pruned.
    fresh = _dcr_app("fresh.example.com", created_delta=timedelta(seconds=-1))

    call_command("cleardcrapplications", min_age_days=0)

    assert not Application.objects.filter(pk=fresh.pk).exists()
    assert "Deleted 1 orphaned DCR application(s)" in capsys.readouterr().out


@pytest.mark.django_db(databases="__all__")
def test_cleardcrapplications_default_min_age_spares_recent_rows(capsys):
    # A tokenless DCR app registered inside the default 7-day grace window is
    # spared, guarding a client that registered but has not yet authorized.
    recent = _dcr_app("recent.example.com", created_delta=timedelta(days=-3))

    call_command("cleardcrapplications")

    assert Application.objects.filter(pk=recent.pk).exists()
    assert "Deleted 0 orphaned DCR application(s)" in capsys.readouterr().out


@pytest.mark.parametrize("batch_size", [0, -1])
def test_cleardcrapplications_rejects_non_positive_batch_size(batch_size):
    with pytest.raises(CommandError, match="--batch-size"):
        call_command("cleardcrapplications", batch_size=batch_size)


def test_cleardcrapplications_rejects_negative_min_age_days():
    with pytest.raises(CommandError, match="--min-age-days"):
        call_command("cleardcrapplications", min_age_days=-1)


@pytest.mark.django_db(databases="__all__")
def test_cleardcrapplications_skips_row_whose_source_changed_mid_run(mocker):
    """A row that stops being DCR between the candidate scan and the locked
    re-check must not be deleted: the locked query re-applies the
    registration_source filter, not just the age cutoff.
    """
    from django.db import transaction as real_transaction

    app = _dcr_app("mutated.example.com")  # DCR + aged, no live tokens

    real_atomic = real_transaction.atomic

    def flip_then_atomic(*args, **kwargs):
        # Simulate registration_source changing (data correction / custom code)
        # after the candidate query selected this row but before the lock.
        Application.objects.filter(pk=app.pk).update(
            registration_source=Application.RegistrationSource.MANUAL
        )
        return real_atomic(*args, **kwargs)

    mocker.patch(
        "oauth2_provider.management.commands.cleardcrapplications.transaction.atomic",
        side_effect=flip_then_atomic,
    )

    call_command("cleardcrapplications")

    # The row is no longer DCR by lock time, so it is left untouched.
    assert Application.objects.filter(pk=app.pk).exists()


@pytest.mark.django_db(databases="__all__")
def test_cleardcrapplications_ignores_the_rfc_7592_registration_token(capsys):
    # Every DCR application is issued a registration access token whose default
    # expiry is year 9999. Counting it as a live token would keep every ghost
    # alive forever, so it must not spare the application.
    from oauth2_provider.settings import oauth2_settings

    ghost = _dcr_app("registration-token.example.com")
    get_access_token_model().objects.create(
        token="registration-at",
        expires=datetime(9999, 12, 31, 23, 59, 59, tzinfo=dt_timezone.utc),
        application=ghost,
        scope=oauth2_settings.DCR_REGISTRATION_SCOPE,
    )
    # A token that merely also carries the registration scope is a real token
    # and still counts as live.
    live = _dcr_app("registration-plus.example.com")
    get_access_token_model().objects.create(
        token="registration-plus-at",
        expires=timezone.now() + timedelta(hours=1),
        application=live,
        scope=f"{oauth2_settings.DCR_REGISTRATION_SCOPE} read",
    )

    call_command("cleardcrapplications")

    assert not Application.objects.filter(pk=ghost.pk).exists()
    assert Application.objects.filter(pk=live.pk).exists()
    assert "Deleted 1 orphaned DCR application(s)" in capsys.readouterr().out


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.DCR_SETTINGS)
class TestClearDCRApplicationsAgainstTheRegistrationEndpoint(TestCase):
    """The prune path, exercised against an application registered through the
    DCR endpoint rather than built directly, so it carries the registration
    access token a real ghost holds.
    """

    def test_ghost_registered_through_the_endpoint_is_pruned(self):
        user = UserModel.objects.create_user("dcr_prune_user", "dcr-prune@example.com", "pass")
        self.client.force_login(user)
        response = self.client.post(
            reverse("oauth2_provider:dcr-register"),
            data=json.dumps(
                {
                    "redirect_uris": ["https://client.example.com/cb"],
                    "grant_types": ["authorization_code"],
                }
            ),
            content_type="application/json",
        )
        assert response.status_code == 201
        app = Application.objects.get(client_id=response.json()["client_id"])
        assert get_access_token_model().objects.filter(application=app).exists()
        Application.objects.filter(pk=app.pk).update(created=timezone.now() - timedelta(days=30))

        out = StringIO()
        call_command("cleardcrapplications", stdout=out)

        assert not Application.objects.filter(pk=app.pk).exists()
        assert "Deleted 1 orphaned DCR application(s)" in out.getvalue()
