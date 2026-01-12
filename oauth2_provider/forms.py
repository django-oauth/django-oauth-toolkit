from django import forms
from django.contrib.auth.hashers import identify_hasher
from django.utils.translation import gettext_lazy as _


def _is_hashed(secret):
    """Return True if ``secret`` is a recognized password hash (not cleartext)."""
    if not secret:
        return False
    try:
        identify_hasher(secret)
    except ValueError:
        return False
    return True


class AllowForm(forms.Form):
    allow = forms.BooleanField(required=False)
    redirect_uri = forms.CharField(widget=forms.HiddenInput())
    scope = forms.CharField(widget=forms.HiddenInput())
    nonce = forms.CharField(required=False, widget=forms.HiddenInput())
    client_id = forms.CharField(widget=forms.HiddenInput())
    state = forms.CharField(required=False, widget=forms.HiddenInput())
    response_type = forms.CharField(widget=forms.HiddenInput())
    code_challenge = forms.CharField(required=False, widget=forms.HiddenInput())
    code_challenge_method = forms.CharField(required=False, widget=forms.HiddenInput())
    claims = forms.CharField(required=False, widget=forms.HiddenInput())
    resource = forms.CharField(required=False, widget=forms.HiddenInput())  # RFC 8707


class ConfirmLogoutForm(forms.Form):
    allow = forms.BooleanField(required=False)
    id_token_hint = forms.CharField(required=False, widget=forms.HiddenInput())
    logout_hint = forms.CharField(required=False, widget=forms.HiddenInput())
    client_id = forms.CharField(required=False, widget=forms.HiddenInput())
    post_logout_redirect_uri = forms.CharField(required=False, widget=forms.HiddenInput())
    state = forms.CharField(required=False, widget=forms.HiddenInput())
    ui_locales = forms.CharField(required=False, widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop("request", None)
        super(ConfirmLogoutForm, self).__init__(*args, **kwargs)


class ApplicationForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # These run independently: the client_secret help handling may short-circuit
        # (e.g. an already-hashed secret), but the HS256 warning must still be wired.
        self._init_client_secret_help()
        self._init_hs256_warning()

    def _init_client_secret_help(self):
        # This form is normally bound to the (swappable) application model via
        # ``modelform_factory``; guard against field sets that omit client_secret.
        if "client_secret" not in self.fields:
            return
        # Hashing is optional per-application (``hash_client_secret``); when it is
        # disabled the secret is stored as-is and stays readable, so the warnings
        # about hashing / unrecoverability only apply when the secret is (or will
        # be) hashed.
        existing = bool(self.instance and self.instance.pk)
        if existing and _is_hashed(self.instance.client_secret):
            # Already hashed. This cannot be undone, so the flag is irrelevant here
            # and there is nothing for the live toggle to swap.
            self.fields["client_secret"].help_text = _(
                "The client secret is hashed and can no longer be viewed. "
                "To rotate it, enter a new value and copy it before saving; "
                "the original secret cannot be recovered."
            )
            return
        # The secret is currently readable. Which warning applies depends on whether
        # it will be hashed on save, which the user toggles via hash_client_secret.
        # Expose both messages so the template can swap them live as the checkbox
        # changes; the server picks the correct one for the initial / no-JS render.
        self.client_secret_help_when_hashed = _(
            "Copy and store this secret now. Once saved, it will be hashed and cannot be recovered."
        )
        if existing:
            self.client_secret_help_when_unhashed = _(
                "This application stores its client secret unhashed, so the value above "
                "remains usable. Entering a new value replaces it."
            )
        else:
            self.client_secret_help_when_unhashed = _(
                "Copy and store this secret now. This application stores the secret unhashed."
            )
        self.fields["client_secret"].help_text = (
            self.client_secret_help_when_hashed
            if self._will_hash_client_secret()
            else self.client_secret_help_when_unhashed
        )
        # Expose both variants on the hash_client_secret checkbox as data-attributes
        # so the shared application_form.js can swap the client_secret help text live
        # as the box is toggled. Rendered identically by the front-end views and the
        # Django admin, so both surfaces behave the same. Only emitted while the
        # secret is still readable; the already-hashed branch returns above (there is
        # nothing to toggle), leaving the checkbox without these attributes.
        if "hash_client_secret" in self.fields:
            self.fields["hash_client_secret"].widget.attrs.update(
                {
                    "data-client-secret-help-when-hashed": self.client_secret_help_when_hashed,
                    "data-client-secret-help-when-unhashed": self.client_secret_help_when_unhashed,
                }
            )

    def _init_hs256_warning(self):
        # HS256 uses the client secret as the HMAC signing key, so the secret must be
        # stored unhashed; Application.clean() rejects HS256 + a hashed secret, but only
        # at save time. Expose what the shared application_form.js needs to warn live
        # (as the algorithm / hash checkbox / secret change) so the misconfiguration is
        # visible immediately rather than only after a failed save. Unlike the
        # client_secret help above, this is wired even when the secret is already hashed
        # -- that is exactly the case that needs the warning.
        if "algorithm" not in self.fields:
            return
        model = type(self.instance)
        stored_hashed = bool(self.instance and self.instance.pk and _is_hashed(self.instance.client_secret))
        self.fields["algorithm"].widget.attrs.update(
            {
                "data-hs256-value": model.HS256_ALGORITHM,
                "data-client-secret-stored-hashed": "true" if stored_hashed else "false",
                "data-hs256-hashed-secret-warning": _(
                    "HS256 signs tokens with the client secret as the HMAC key, so the secret must "
                    "be stored unhashed. Uncheck “Hash client secret” and set an unhashed "
                    "client secret, or choose a different algorithm."
                ),
                # Shown next to the hash_client_secret checkbox as well, so the conflict is
                # flagged from both fields (application_form.js renders both).
                "data-hs256-hash-checkbox-warning": _(
                    "HS256 requires an unhashed client secret. Uncheck this and set an unhashed "
                    "client secret, or choose a different algorithm."
                ),
            }
        )

    class Media:
        js = ("oauth2_provider/js/application_form.js",)

    def _will_hash_client_secret(self):
        """Whether the client secret will be hashed on save.

        Honors the submitted value so the help text stays correct when the form
        is re-rendered after a failed POST; otherwise falls back to the
        instance/model default.
        """
        if self.is_bound and "hash_client_secret" in self.fields:
            return self.fields["hash_client_secret"].widget.value_from_datadict(
                self.data, self.files, self.add_prefix("hash_client_secret")
            )
        return getattr(self.instance, "hash_client_secret", True)
