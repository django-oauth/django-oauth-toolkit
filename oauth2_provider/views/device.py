import json

from django import forms, http
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import DetailView, FormView, View
from oauthlib.oauth2 import DeviceApplicationServer

from oauth2_provider.compat import login_not_required
from oauth2_provider.models import (
    DeviceCodeResponse,
    DeviceGrant,
    DeviceRequest,
    create_device_grant,
    get_device_grant_model,
)
from oauth2_provider.views.mixins import OAuthLibMixin


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class DeviceAuthorizationView(OAuthLibMixin, View):
    server_class = DeviceApplicationServer

    def post(self, request, *args, **kwargs):
        headers, response, status = self.create_device_authorization_response(request)

        if status != 200:
            return http.JsonResponse(data=json.loads(response), status=status, headers=headers)

        device_request = DeviceRequest(client_id=request.POST["client_id"], scope=request.POST.get("scope"))
        device_response = DeviceCodeResponse(**response)
        create_device_grant(device_request, device_response)

        return http.JsonResponse(data=response, status=status, headers=headers)


class DeviceGrantForm(forms.Form):
    user_code = forms.CharField(required=True)

    def clean_user_code(self):
        """
        Performs validation on the user_code provided by the user and adds to the cleaned_data dict
        the "device_grant" object associated with the user_code, which is useful to process the
        response in the DeviceUserCodeView.

        It can raise one of the following ValidationErrors, with the associated codes:

        * incorrect_user_code: if a device grant associated with the user_code does not exist
        * expired_user_code: if the device grant associated with the user_code has expired
        * user_code_already_used: if the device grant associated with the user_code has been already
         approved or denied. The only accepted state of the device grant is AUTHORIZATION_PENDING.
        """
        cleaned_data = super().clean()
        user_code: str = cleaned_data["user_code"]
        try:
            device_grant: DeviceGrant = get_device_grant_model().objects.get(user_code=user_code)
        except DeviceGrant.DoesNotExist:
            raise ValidationError("Incorrect user code", code="incorrect_user_code")

        if device_grant.is_expired():
            raise ValidationError("Expired user code", code="expired_user_code")

        # User of device has already made their decision for this device.
        if device_grant.status != device_grant.AUTHORIZATION_PENDING:
            raise ValidationError("User code has already been used", code="user_code_already_used")

        # Make the device_grant available to the View, saving one additional db call.
        cleaned_data["device_grant"] = device_grant

        return user_code


class DeviceUserCodeView(LoginRequiredMixin, FormView):
    """
    The view where the user is instructed (by the device) to come to in order to
    enter the user code. More details in this section of the RFC:
    https://datatracker.ietf.org/doc/html/rfc8628#section-3.3

    Note: it's common to see in other implementations of this RFC that only ask the
    user to sign in after they input the user code but since the user has to be signed
    in regardless, to approve the device login we're making the decision here, for
    simplicity, to require being logged in up front.
    """

    template_name = "oauth2_provider/device/user_code.html"
    form_class = DeviceGrantForm

    def get_success_url(self):
        return reverse(
            "oauth2_provider:device-confirm",
            kwargs={
                "client_id": self.device_grant.client_id,
                "user_code": self.device_grant.user_code,
            },
        )

    def form_valid(self, form):
        """
        Sets the device_grant on the instance so that it can be accessed
        in get_success_url. It comes in handy when users want to overwrite
        get_success_url, redirecting to the URL with the URL params pointing
        to the current device.
        """
        device_grant: DeviceGrant = form.cleaned_data["device_grant"]

        device_grant.user = self.request.user
        device_grant.save(update_fields=["user"])

        self.device_grant = device_grant

        return super().form_valid(form)


class DeviceConfirmForm(forms.Form):
    """
    Simple form for the user to approve or deny the device.
    """

    action = forms.CharField(required=True)


class DeviceConfirmView(LoginRequiredMixin, FormView):
    """
    The view where the user approves or denies a device.
    """

    template_name = "oauth2_provider/device/accept_deny.html"
    form_class = DeviceConfirmForm

    def get_object(self):
        """
        Returns the DeviceGrant object in the AUTHORIZATION_PENDING state identified
        by the slugs client_id and user_code. Raises Http404 if not found.
        """
        client_id, user_code = self.kwargs.get("client_id"), self.kwargs.get("user_code")
        return get_object_or_404(
            DeviceGrant,
            client_id=client_id,
            user_code=user_code,
            status=DeviceGrant.AUTHORIZATION_PENDING,
        )

    def get_success_url(self):
        return reverse(
            "oauth2_provider:device-grant-status",
            kwargs={
                "client_id": self.kwargs["client_id"],
                "user_code": self.kwargs["user_code"],
            },
        )

    def get(self, request, *args, **kwargs):
        """
        Enable GET requests for improved user experience. But validate that the URL params
        are correct (i.e. there exists a device grant in the db that corresponds to the URL
        params) by calling .get_object()
        """
        _ = self.get_object()  # raises 404 if URL parameters are incorrect
        return super().get(request, args, kwargs)

    def form_valid(self, form):
        """
        Uses get_object() to retrieves the DeviceGrant object and updates its state
        to authorized or denied, based on the user input.
        """
        device = self.get_object()
        action = form.cleaned_data["action"]

        if action == "accept":
            device.status = device.AUTHORIZED
            device.save(update_fields=["status"])
            return super().form_valid(form)
        elif action == "deny":
            device.status = device.DENIED
            device.save(update_fields=["status"])
            return super().form_valid(form)
        else:
            return http.HttpResponseBadRequest()


class DeviceGrantStatusView(LoginRequiredMixin, DetailView):
    """
    The view to display the status of a DeviceGrant.
    """

    model = DeviceGrant
    template_name = "oauth2_provider/device/device_grant_status.html"

    def get_object(self):
        client_id, user_code = self.kwargs.get("client_id"), self.kwargs.get("user_code")
        return get_object_or_404(DeviceGrant, client_id=client_id, user_code=user_code)
