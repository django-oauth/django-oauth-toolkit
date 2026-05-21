from django import forms
from django.forms.models import modelform_factory
from .models import get_application_model


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
        if self.instance and self.instance.pk:
            self.fields["client_secret"].help_text = (
                "⚠️ The client secret has been hashed and can no longer be viewed. "
                "If you need the original value, you must regenerate it and save it immediately."
            )
        else:
            self.fields["client_secret"].help_text = (
                "⚠️ Copy and store this secret now. "
                "Once saved, it will be hashed and cannot be recovered."
            )