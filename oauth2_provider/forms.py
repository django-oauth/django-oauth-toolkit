from django import forms


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
