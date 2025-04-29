from django.contrib.auth.mixins import LoginRequiredMixin
from django.forms.models import modelform_factory
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from oauth2_provider.authorization_server.forms import ApplicationForm
from oauth2_provider.models import get_application_model
from oauth2_provider.settings import oauth2_settings


APPLICATION_FIELDS = (
    "name",
    "client_id",
    "client_secret",
    "hash_client_secret",
    "client_type",
    "authorization_grant_type",
    "redirect_uris",
    "post_logout_redirect_uris",
    "allowed_origins",
    "algorithm",
)


class ApplicationOwnerIsUserMixin(LoginRequiredMixin):
    """
    This mixin is used to provide an Application queryset filtered by the current request.user.
    """

    fields = "__all__"

    def get_queryset(self):
        return get_application_model().objects.filter(user=self.request.user)


class ApplicationEditorMixin(LoginRequiredMixin):
    """
    Builds the form used to create and update an Application.

    The editable field set is not static: fields backing an optional feature are only
    offered when that feature is enabled, so a deployment that does not use it is not
    asked to fill in a field that would be ignored.
    """

    def get_form_class(self):
        fields = list(APPLICATION_FIELDS)

        if oauth2_settings.OIDC_BACKCHANNEL_LOGOUT_ENABLED:
            fields.append("backchannel_logout_uri")

        return modelform_factory(get_application_model(), form=ApplicationForm, fields=fields)


class ApplicationRegistration(ApplicationEditorMixin, CreateView):
    """
    View used to register a new Application for the request.user
    """

    template_name = "oauth2_provider/application_registration_form.html"

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)


class ApplicationDetail(ApplicationOwnerIsUserMixin, DetailView):
    """
    Detail view for an application instance owned by the request.user
    """

    context_object_name = "application"
    template_name = "oauth2_provider/application_detail.html"


class ApplicationList(ApplicationOwnerIsUserMixin, ListView):
    """
    List view for all the applications owned by the request.user
    """

    context_object_name = "applications"
    template_name = "oauth2_provider/application_list.html"


class ApplicationDelete(ApplicationOwnerIsUserMixin, DeleteView):
    """
    View used to delete an application owned by the request.user
    """

    context_object_name = "application"
    success_url = reverse_lazy("oauth2_provider:list")
    template_name = "oauth2_provider/application_confirm_delete.html"


class ApplicationUpdate(ApplicationOwnerIsUserMixin, ApplicationEditorMixin, UpdateView):
    """
    View used to update an application owned by the request.user
    """

    context_object_name = "application"
    template_name = "oauth2_provider/application_form.html"
