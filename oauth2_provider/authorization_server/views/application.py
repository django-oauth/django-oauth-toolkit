from django.contrib.auth.mixins import LoginRequiredMixin
from django.forms.models import modelform_defines_fields, modelform_factory
from django.urls import reverse_lazy
from django.views.generic import CreateView, DeleteView, DetailView, ListView, UpdateView

from oauth2_provider.authorization_server.forms import APPLICATION_FIELDS
from oauth2_provider.models import get_application_model
from oauth2_provider.settings import oauth2_settings


class ApplicationFormMixin:
    """Form handling shared by the application create and update views."""

    # Default field set, used when the configured form declares no Meta.fields / Meta.exclude.
    fields = APPLICATION_FIELDS

    def get_form_class(self):
        """Build the ModelForm used by the registration and update views.

        The form named by ``APPLICATION_FORM_CLASS`` is rebound to the configured
        (swappable) application model. A form declaring its own ``Meta.fields`` /
        ``Meta.exclude`` keeps that field set -- how extra fields on a swapped model
        reach these views; otherwise ``fields`` (``APPLICATION_FIELDS``) applies, which
        is why simply adding a field to a swapped model does not put it on the form.
        """
        # Honour the standard CreateView/UpdateView hook for subclassers; used verbatim,
        # as upstream does.
        if self.form_class:
            return self.form_class
        form_class = oauth2_settings.APPLICATION_FORM_CLASS
        model = get_application_model()
        if modelform_defines_fields(form_class):
            return modelform_factory(model, form=form_class)
        return modelform_factory(model, form=form_class, fields=self.fields)

    def form_valid(self, form):
        # The application is always owned by the request user; a configured form exposing
        # "user" must not turn either view into an ownership transfer.
        form.instance.user = self.request.user
        return super().form_valid(form)


class ApplicationOwnerIsUserMixin(LoginRequiredMixin):
    """
    This mixin is used to provide an Application queryset filtered by the current request.user.
    """

    def get_queryset(self):
        return get_application_model().objects.filter(user=self.request.user)


class ApplicationRegistration(LoginRequiredMixin, ApplicationFormMixin, CreateView):
    """
    View used to register a new Application for the request.user
    """

    template_name = "oauth2_provider/application_registration_form.html"


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


class ApplicationUpdate(ApplicationOwnerIsUserMixin, ApplicationFormMixin, UpdateView):
    """
    View used to update an application owned by the request.user
    """

    context_object_name = "application"
    template_name = "oauth2_provider/application_form.html"
