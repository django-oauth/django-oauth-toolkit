from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy
from django.views.generic import DeleteView, ListView

from ..models import get_access_token_model


class AuthorizedTokensListView(LoginRequiredMixin, ListView):
    """
    Show a page where the current logged-in user can see his tokens so they can revoke them
    """

    context_object_name = "authorized_tokens"
    template_name = "oauth2_provider/authorized-tokens.html"
    model = get_access_token_model()

    def get_queryset(self):
        """
        Show only user's tokens
        """
        return super().get_queryset().select_related("application").filter(user=self.request.user)


class AuthorizedTokenDeleteView(LoginRequiredMixin, DeleteView):
    """
    View for revoking a specific token
    """

    template_name = "oauth2_provider/authorized-token-delete.html"
    success_url = reverse_lazy("oauth2_provider:authorized-token-list")
    model = get_access_token_model()

    def get_queryset(self):
        return super().get_queryset().filter(user=self.request.user)

    def form_valid(self, form):
        """
        Revoke the access token and its associated refresh token.

        Deleting the access token on its own leaves the refresh token usable
        (the ``RefreshToken.access_token`` FK is ``SET_NULL``), so it can still be
        exchanged for a fresh access token, defeating the revocation. Per
        :rfc:`7009#section-2.1` revoking an access token may also revoke the
        respective refresh token; for a user-initiated "revoke access" action that
        is the only unsurprising behavior. Revoking the refresh token also deletes
        the bound access token, so it covers both.
        """
        access_token = self.get_object()
        try:
            refresh_token = access_token.refresh_token
        except ObjectDoesNotExist:
            refresh_token = None

        if refresh_token is not None:
            refresh_token.revoke()
        else:
            access_token.revoke()

        return HttpResponseRedirect(self.get_success_url())
