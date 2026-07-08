import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.forms.models import modelform_factory
from django.urls import reverse

from oauth2_provider.forms import ApplicationForm, _is_hashed
from oauth2_provider.models import get_application_model
from oauth2_provider.views.application import ApplicationRegistration

from .common_testing import OAuth2ProviderTestCase as TestCase
from .models import SampleApplication


Application = get_application_model()
UserModel = get_user_model()


class BaseTest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.foo_user = UserModel.objects.create_user("foo_user", "test@example.com", "123456")
        cls.bar_user = UserModel.objects.create_user("bar_user", "dev@example.com", "123456")


@pytest.mark.usefixtures("oauth2_settings")
class TestApplicationRegistrationView(BaseTest):
    @pytest.mark.oauth2_settings({"APPLICATION_MODEL": "tests.SampleApplication"})
    def test_get_form_class(self):
        """
        Tests that the form class returned by the "get_form_class" method is
        bound to custom application model defined in the
        "OAUTH2_PROVIDER_APPLICATION_MODEL" setting.
        """
        # Create a registration view and tests that the model form is bound
        # to the custom Application model
        application_form_class = ApplicationRegistration().get_form_class()
        self.assertEqual(SampleApplication, application_form_class._meta.model)

    def test_application_registration_user(self):
        self.client.login(username="foo_user", password="123456")

        form_data = {
            "name": "Foo app",
            "client_id": "client_id",
            "client_secret": "client_secret",
            "client_type": Application.CLIENT_CONFIDENTIAL,
            "redirect_uris": "http://example.com",
            "post_logout_redirect_uris": "http://other_example.com",
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "algorithm": "",
        }

        response = self.client.post(reverse("oauth2_provider:register"), form_data)
        self.assertEqual(response.status_code, 302)

        app = get_application_model().objects.get(name="Foo app")
        self.assertEqual(app.user.username, "foo_user")
        app = Application.objects.get()
        self.assertEqual(app.name, form_data["name"])
        self.assertEqual(app.client_id, form_data["client_id"])
        self.assertEqual(app.redirect_uris, form_data["redirect_uris"])
        self.assertEqual(app.post_logout_redirect_uris, form_data["post_logout_redirect_uris"])
        self.assertEqual(app.client_type, form_data["client_type"])
        self.assertEqual(app.authorization_grant_type, form_data["authorization_grant_type"])
        self.assertEqual(app.algorithm, form_data["algorithm"])


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings({"ALLOW_URI_WILDCARDS": True})
class TestApplicationRegistrationViewRedirectURIWithWildcard(BaseTest):
    def _test_valid(self, redirect_uri):
        self.client.login(username="foo_user", password="123456")

        form_data = {
            "name": "Foo app",
            "client_id": "client_id",
            "client_secret": "client_secret",
            "client_type": Application.CLIENT_CONFIDENTIAL,
            "redirect_uris": redirect_uri,
            "post_logout_redirect_uris": "http://example.com",
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "algorithm": "",
        }

        response = self.client.post(reverse("oauth2_provider:register"), form_data)
        self.assertEqual(response.status_code, 302)

        app = get_application_model().objects.get(name="Foo app")
        self.assertEqual(app.user.username, "foo_user")
        app = Application.objects.get()
        self.assertEqual(app.name, form_data["name"])
        self.assertEqual(app.client_id, form_data["client_id"])
        self.assertEqual(app.redirect_uris, form_data["redirect_uris"])
        self.assertEqual(app.post_logout_redirect_uris, form_data["post_logout_redirect_uris"])
        self.assertEqual(app.client_type, form_data["client_type"])
        self.assertEqual(app.authorization_grant_type, form_data["authorization_grant_type"])
        self.assertEqual(app.algorithm, form_data["algorithm"])

    def _test_invalid(self, uri, error_message):
        self.client.login(username="foo_user", password="123456")

        form_data = {
            "name": "Foo app",
            "client_id": "client_id",
            "client_secret": "client_secret",
            "client_type": Application.CLIENT_CONFIDENTIAL,
            "redirect_uris": uri,
            "post_logout_redirect_uris": "http://example.com",
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "algorithm": "",
        }

        response = self.client.post(reverse("oauth2_provider:register"), form_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, error_message)

    def test_application_registration_valid_3ld_wildcard(self):
        self._test_valid("https://*.example.com")

    def test_application_registration_valid_3ld_partial_wildcard(self):
        self._test_valid("https://*-partial.example.com")

    def test_application_registration_invalid_star(self):
        self._test_invalid("*", "invalid_scheme: *")

    def test_application_registration_invalid_tld_wildcard(self):
        self._test_invalid("https://*", "wildcards cannot be in the top level or second level domain")

    def test_application_registration_invalid_tld_partial_wildcard(self):
        self._test_invalid("https://*-partial", "wildcards cannot be in the top level or second level domain")

    def test_application_registration_invalid_tld_not_startswith_wildcard_tld(self):
        self._test_invalid("https://example.*", "wildcards must be at the beginning of the hostname")

    def test_application_registration_invalid_2ld_wildcard(self):
        self._test_invalid("https://*.com", "wildcards cannot be in the top level or second level domain")

    def test_application_registration_invalid_2ld_partial_wildcard(self):
        self._test_invalid(
            "https://*-partial.com", "wildcards cannot be in the top level or second level domain"
        )

    def test_application_registration_invalid_2ld_not_startswith_wildcard_tld(self):
        self._test_invalid("https://example.*.com", "wildcards must be at the beginning of the hostname")

    def test_application_registration_invalid_3ld_partial_not_startswith_wildcard_2ld(self):
        self._test_invalid(
            "https://invalid-*.example.com", "wildcards must be at the beginning of the hostname"
        )

    def test_application_registration_invalid_4ld_not_startswith_wildcard_3ld(self):
        self._test_invalid(
            "https://invalid.*.invalid.example.com",
            "wildcards must be at the beginning of the hostname",
        )

    def test_application_registration_invalid_4ld_partial_not_startswith_wildcard_2ld(self):
        self._test_invalid(
            "https://invalid-*.invalid.example.com",
            "wildcards must be at the beginning of the hostname",
        )


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings({"ALLOW_URI_WILDCARDS": True})
class TestApplicationRegistrationViewAllowedOriginWithWildcard(
    TestApplicationRegistrationViewRedirectURIWithWildcard
):
    def _test_valid(self, uris):
        self.client.login(username="foo_user", password="123456")

        form_data = {
            "name": "Foo app",
            "client_id": "client_id",
            "client_secret": "client_secret",
            "client_type": Application.CLIENT_CONFIDENTIAL,
            "allowed_origins": uris,
            "redirect_uris": "https://example.com",
            "post_logout_redirect_uris": "http://example.com",
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "algorithm": "",
        }

        response = self.client.post(reverse("oauth2_provider:register"), form_data)
        self.assertEqual(response.status_code, 302)

        app = get_application_model().objects.get(name="Foo app")
        self.assertEqual(app.user.username, "foo_user")
        app = Application.objects.get()
        self.assertEqual(app.name, form_data["name"])
        self.assertEqual(app.client_id, form_data["client_id"])
        self.assertEqual(app.redirect_uris, form_data["redirect_uris"])
        self.assertEqual(app.post_logout_redirect_uris, form_data["post_logout_redirect_uris"])
        self.assertEqual(app.client_type, form_data["client_type"])
        self.assertEqual(app.authorization_grant_type, form_data["authorization_grant_type"])
        self.assertEqual(app.algorithm, form_data["algorithm"])

    def _test_invalid(self, uri, error_message):
        self.client.login(username="foo_user", password="123456")

        form_data = {
            "name": "Foo app",
            "client_id": "client_id",
            "client_secret": "client_secret",
            "client_type": Application.CLIENT_CONFIDENTIAL,
            "allowed_origins": uri,
            "redirect_uris": "http://example.com",
            "post_logout_redirect_uris": "http://example.com",
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "algorithm": "",
        }

        response = self.client.post(reverse("oauth2_provider:register"), form_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, error_message)


class TestApplicationViews(BaseTest):
    @classmethod
    def _create_application(cls, name, user):
        return Application.objects.create(
            name=name,
            redirect_uris="http://example.com",
            post_logout_redirect_uris="http://other_example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=user,
        )

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.app_foo_1 = cls._create_application("app foo_user 1", cls.foo_user)
        cls.app_foo_2 = cls._create_application("app foo_user 2", cls.foo_user)
        cls.app_foo_3 = cls._create_application("app foo_user 3", cls.foo_user)

        cls.app_bar_1 = cls._create_application("app bar_user 1", cls.bar_user)
        cls.app_bar_2 = cls._create_application("app bar_user 2", cls.bar_user)

    def test_application_list(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse("oauth2_provider:list"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["object_list"]), 3)

    def test_application_detail_owner(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse("oauth2_provider:detail", args=(self.app_foo_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.app_foo_1.name)
        self.assertContains(response, self.app_foo_1.redirect_uris)
        self.assertContains(response, self.app_foo_1.post_logout_redirect_uris)
        self.assertContains(response, self.app_foo_1.client_type)
        self.assertContains(response, self.app_foo_1.authorization_grant_type)

    def test_application_detail_not_owner(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse("oauth2_provider:detail", args=(self.app_bar_1.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_application_update(self):
        self.client.login(username="foo_user", password="123456")

        form_data = {
            "client_id": "new_client_id",
            "redirect_uris": "http://new_example.com",
            "post_logout_redirect_uris": "http://new_other_example.com",
            "client_type": Application.CLIENT_PUBLIC,
            "authorization_grant_type": Application.GRANT_OPENID_HYBRID,
        }
        response = self.client.post(
            reverse("oauth2_provider:update", args=(self.app_foo_1.pk,)),
            data=form_data,
        )
        self.assertRedirects(response, reverse("oauth2_provider:detail", args=(self.app_foo_1.pk,)))

        self.app_foo_1.refresh_from_db()
        self.assertEqual(self.app_foo_1.client_id, form_data["client_id"])
        self.assertEqual(self.app_foo_1.redirect_uris, form_data["redirect_uris"])
        self.assertEqual(self.app_foo_1.post_logout_redirect_uris, form_data["post_logout_redirect_uris"])
        self.assertEqual(self.app_foo_1.client_type, form_data["client_type"])
        self.assertEqual(self.app_foo_1.authorization_grant_type, form_data["authorization_grant_type"])

    def test_client_secret_help_text_new_application(self):
        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse("oauth2_provider:register"))
        form = response.context["form"]
        self.assertIn("Copy and store this secret now", form.fields["client_secret"].help_text)
        self.assertContains(response, "Copy and store this secret now")

    def test_client_secret_help_text_existing_application(self):
        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse("oauth2_provider:update", args=(self.app_foo_1.pk,)))
        form = response.context["form"]
        self.assertIn("can no longer be viewed", form.fields["client_secret"].help_text)
        self.assertContains(response, "can no longer be viewed")

    def test_client_secret_help_text_existing_application_unhashed(self):
        # Create with hashing disabled from the start so the stored secret stays cleartext.
        app = Application.objects.create(
            name="app foo_user unhashed",
            redirect_uris="http://example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=self.foo_user,
            hash_client_secret=False,
            client_secret="cleartext-secret",
        )
        self.assertEqual(app.client_secret, "cleartext-secret")  # sanity: not hashed on save
        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse("oauth2_provider:update", args=(app.pk,)))
        form = response.context["form"]
        self.assertIn("stores its client secret unhashed", form.fields["client_secret"].help_text)
        self.assertContains(response, "stores its client secret unhashed")

    def test_client_secret_help_text_existing_application_hashed_after_disable(self):
        # Disabling hash_client_secret does not unhash an already-hashed stored secret,
        # so the edit form must still show the "hashed / cannot be viewed" message.
        app = self._create_application("app foo_user was hashed", self.foo_user)
        self.assertTrue(app.hash_client_secret)  # hashed on create by default
        app.hash_client_secret = False
        app.save()
        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse("oauth2_provider:update", args=(app.pk,)))
        form = response.context["form"]
        self.assertIn("can no longer be viewed", form.fields["client_secret"].help_text)

    def test_client_secret_help_text_existing_unhashed_enabling_hashing(self):
        # Existing cleartext secret + hashing being enabled (e.g. failed-POST
        # re-render): the secret will be hashed on save, so the form must warn
        # rather than say the value "remains usable".
        app = Application.objects.create(
            name="app foo_user enabling hashing",
            redirect_uris="http://example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=self.foo_user,
            hash_client_secret=False,
            client_secret="cleartext-secret",
        )
        form_class = ApplicationRegistration().get_form_class()
        form = form_class(data={"hash_client_secret": "on"}, instance=app)
        self.assertIn("it will be hashed and cannot be recovered", form.fields["client_secret"].help_text)

    def test_client_secret_help_text_new_application_unhashed(self):
        form_class = ApplicationRegistration().get_form_class()
        form = form_class(instance=Application(hash_client_secret=False))
        self.assertIn("stores the secret unhashed", form.fields["client_secret"].help_text)

    def test_client_secret_help_text_new_application_honors_submitted_value(self):
        # After a failed POST the help text should reflect the submitted
        # hash_client_secret value, not just the model default.
        form_class = ApplicationRegistration().get_form_class()
        form = form_class(data={"name": "incomplete"})  # bound, hash checkbox unchecked -> False
        self.assertIn("stores the secret unhashed", form.fields["client_secret"].help_text)

    def test_client_secret_help_text_live_toggle_rendered_on_register(self):
        # The register page must ship both help variants (as checkbox data-attributes)
        # plus the shared application_form.js so the message updates live as
        # hash_client_secret is toggled, rather than being frozen at the
        # server-rendered value.
        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse("oauth2_provider:register"))
        self.assertContains(response, "data-client-secret-help-when-hashed")
        self.assertContains(response, "data-client-secret-help-when-unhashed")
        self.assertContains(response, "it will be hashed and cannot be recovered")
        self.assertContains(response, "stores the secret unhashed")
        self.assertContains(response, "id_hash_client_secret")
        self.assertContains(response, "oauth2_provider/js/application_form.js")

    def test_client_secret_help_text_no_live_toggle_when_already_hashed(self):
        # An already-hashed secret cannot be reverted by unchecking the box, so the
        # toggle data-attributes must not be rendered on that edit page.
        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse("oauth2_provider:update", args=(self.app_foo_1.pk,)))
        self.assertContains(response, "can no longer be viewed")
        self.assertNotContains(response, "data-client-secret-help-when-hashed")

    def test_application_form_without_client_secret_field(self):
        # ApplicationForm must not assume client_secret / hash_client_secret are
        # present in the field set when used as a modelform_factory base.
        form_class = modelform_factory(Application, form=ApplicationForm, fields=("name",))
        form_class()  # should not raise KeyError

    def test_is_hashed_helper(self):
        self.assertFalse(_is_hashed(""))  # empty/falsy
        self.assertFalse(_is_hashed(None))  # None (guards against identify_hasher TypeError)
        self.assertFalse(_is_hashed("cleartext-secret"))  # unrecognized -> ValueError
        self.assertTrue(_is_hashed(make_password("cleartext-secret")))  # real hash

    def test_hs256_warning_attrs_new_application(self):
        # The algorithm field carries the data the live HS256 warning needs, including
        # the message shown next to the hash_client_secret checkbox.
        form = ApplicationRegistration().get_form_class()(instance=Application())
        attrs = form.fields["algorithm"].widget.attrs
        self.assertEqual(attrs.get("data-hs256-value"), Application.HS256_ALGORITHM)
        self.assertEqual(attrs.get("data-client-secret-stored-hashed"), "false")
        self.assertIn("must be stored unhashed", str(attrs.get("data-hs256-hashed-secret-warning")))
        self.assertIn(
            "HS256 requires an unhashed client secret",
            str(attrs.get("data-hs256-hash-checkbox-warning")),
        )

    def test_hs256_warning_attrs_present_even_when_secret_hashed(self):
        # Regression: an already-hashed secret short-circuits the client_secret help
        # wiring, but the HS256 warning must still be wired -- that is exactly the case
        # (edit an app whose secret is hashed, pick HS256) that needs it.
        self.assertTrue(_is_hashed(self.app_foo_1.client_secret))  # hashed on create by default
        form = ApplicationRegistration().get_form_class()(instance=self.app_foo_1)
        attrs = form.fields["algorithm"].widget.attrs
        self.assertEqual(attrs.get("data-hs256-value"), Application.HS256_ALGORITHM)
        self.assertEqual(attrs.get("data-client-secret-stored-hashed"), "true")

    def test_hs256_warning_rendered_on_register(self):
        self.client.login(username="foo_user", password="123456")
        response = self.client.get(reverse("oauth2_provider:register"))
        self.assertContains(response, 'data-hs256-value="HS256"')
        self.assertContains(response, "data-hs256-hashed-secret-warning")
        self.assertContains(response, "data-hs256-hash-checkbox-warning")
        self.assertContains(response, "oauth2_provider/js/application_form.js")


class TestApplicationAdminHashClientSecretUX(BaseTest):
    """The admin change form must offer the same hash_client_secret-driven
    client_secret help text (and live toggle) as the front-end views."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.admin_user = UserModel.objects.create_superuser("admin_user", "admin@example.com", "123456")
        cls.hashed_app = Application.objects.create(
            name="hashed app",
            redirect_uris="http://example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=cls.foo_user,
        )
        cls.unhashed_app = Application.objects.create(
            name="unhashed app",
            redirect_uris="http://example.com",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=cls.foo_user,
            hash_client_secret=False,
            client_secret="cleartext-secret",
        )

    def test_admin_add_form_ships_live_toggle(self):
        # A new application's secret is still readable, so the admin add form must
        # expose both help variants and load the shared toggle script.
        self.client.login(username="admin_user", password="123456")
        response = self.client.get(reverse("admin:oauth2_provider_application_add"))
        self.assertContains(response, "data-client-secret-help-when-hashed")
        self.assertContains(response, "data-client-secret-help-when-unhashed")
        self.assertContains(response, "it will be hashed and cannot be recovered")
        self.assertContains(response, "oauth2_provider/js/application_form.js")

    def test_admin_change_form_unhashed_shows_toggle(self):
        # An application that stores its secret unhashed keeps a readable secret,
        # so the admin edit form must still ship the live toggle.
        self.client.login(username="admin_user", password="123456")
        response = self.client.get(
            reverse("admin:oauth2_provider_application_change", args=(self.unhashed_app.pk,))
        )
        self.assertContains(response, "data-client-secret-help-when-hashed")
        self.assertContains(response, "stores its client secret unhashed")
        self.assertContains(response, "oauth2_provider/js/application_form.js")

    def test_admin_change_form_hashed_has_no_toggle(self):
        # An already-hashed secret cannot be reverted, so no live toggle is offered;
        # the admin shows the same static "cannot be viewed" message as the front-end.
        self.client.login(username="admin_user", password="123456")
        response = self.client.get(
            reverse("admin:oauth2_provider_application_change", args=(self.hashed_app.pk,))
        )
        self.assertContains(response, "can no longer be viewed")
        self.assertNotContains(response, "data-client-secret-help-when-hashed")

    def test_admin_change_form_ships_hs256_warning(self):
        # Editing an application whose secret is hashed (the default) and selecting
        # HS256 is invalid; the admin must ship the data the live warning needs, even
        # though the client_secret help toggle is (correctly) absent for a hashed secret.
        self.client.login(username="admin_user", password="123456")
        response = self.client.get(
            reverse("admin:oauth2_provider_application_change", args=(self.hashed_app.pk,))
        )
        self.assertContains(response, 'data-hs256-value="HS256"')
        self.assertContains(response, 'data-client-secret-stored-hashed="true"')
        self.assertContains(response, "must be stored unhashed")
        self.assertContains(response, "oauth2_provider/js/application_form.js")
