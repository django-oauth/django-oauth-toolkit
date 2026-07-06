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
            # Already hashed. This cannot be undone, so the flag is irrelevant here.
            self.fields["client_secret"].help_text = _(
                "The client secret is hashed and can no longer be viewed. "
                "To rotate it, enter a new value and copy it before saving; "
                "the original secret cannot be recovered."
            )
        elif self._will_hash_client_secret():
            # Secret is currently readable but will be hashed on save. Covers a new
            # application and an existing cleartext secret with hashing being enabled
            # (e.g. re-rendered after a failed POST).
            self.fields["client_secret"].help_text = _(
                "Copy and store this secret now. Once saved, it will be hashed and cannot be recovered."
            )
        elif existing:
            self.fields["client_secret"].help_text = _(
                "This application stores its client secret unhashed, so the value above "
                "remains usable. Entering a new value replaces it."
            )
        else:
            self.fields["client_secret"].help_text = _(
                "Copy and store this secret now. This application stores the secret unhashed."
            )

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
