from django.contrib.auth.mixins import LoginRequiredMixin
from django.forms.models import modelform_factory
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

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


def get_application_form_class():
    """Build the ModelForm used by the application registration and update views.

    The base form comes from the ``APPLICATION_FORM_CLASS`` setting and is rebound to
    the configured (swappable) application model, so a form written against
    ``oauth2_provider.Application`` keeps working after the model is swapped.

    A custom form that declares its own ``Meta.fields`` / ``Meta.exclude`` keeps that
    field set: that is how extra fields on a swapped application model reach the
    built-in views. Without one, the fields default to ``APPLICATION_FIELDS`` -- the
    OAuth fields the shipped views have always rendered -- which is why simply adding
    a field to a swapped model does not put it on the form.
    """
    form_class = oauth2_settings.APPLICATION_FORM_CLASS
    opts = getattr(form_class, "_meta", None)
    if opts is not None and (opts.fields is not None or opts.exclude is not None):
        return modelform_factory(get_application_model(), form=form_class)
    return modelform_factory(get_application_model(), form=form_class, fields=APPLICATION_FIELDS)


class ApplicationOwnerIsUserMixin(LoginRequiredMixin):
    """
    This mixin is used to provide an Application queryset filtered by the current request.user.
    """

    fields = "__all__"

    def get_queryset(self):
        return get_application_model().objects.filter(user=self.request.user)


class ApplicationRegistration(LoginRequiredMixin, CreateView):
    """
    View used to register a new Application for the request.user
    """

    template_name = "oauth2_provider/application_registration_form.html"

    def get_form_class(self):
        return get_application_form_class()

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


class ApplicationUpdate(ApplicationOwnerIsUserMixin, UpdateView):
    """
    View used to update an application owned by the request.user
    """

    context_object_name = "application"
    template_name = "oauth2_provider/application_form.html"

    def get_form_class(self):
        return get_application_form_class()
