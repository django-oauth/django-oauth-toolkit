import json

from django import forms, http
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from oauthlib.oauth2 import DeviceApplicationServer
from oauthlib.oauth2.rfc8628.errors import (
    AccessDenied,
    ExpiredTokenError,
)

from oauth2_provider.compat import login_not_required
from oauth2_provider.models import Device, DeviceCodeResponse, DeviceRequest, create_device, get_device_model
from oauth2_provider.views.mixins import OAuthLibMixin


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class DeviceAuthorizationView(OAuthLibMixin, View):
    server_class = DeviceApplicationServer

    def post(self, request, *args, **kwargs):
        headers, response, status = self.create_device_authorization_response(request)

        device_request = DeviceRequest(client_id=request.POST["client_id"], scope=request.POST.get("scope"))

        if status != 200:
            return http.JsonResponse(data=json.loads(response), status=status, headers=headers)

        device_response = DeviceCodeResponse(**response)
        create_device(device_request, device_response)

        return http.JsonResponse(data=response, status=status, headers=headers)


class DeviceForm(forms.Form):
    user_code = forms.CharField(required=True)


# it's common to see in real world products
# device flow's only asking the user to sign in after they input the
# user code but since the user has to be signed in regardless to approve the
# device login we're making the decision here to require being logged in
# up front
@login_required
def device_user_code_view(request):
    form = DeviceForm(request.POST)

    if request.method != "POST":
        return render(request, "oauth2_provider/device/user_code.html", {"form": form})

    if not form.is_valid():
        return render(request, "oauth2_provider/device/user_code.html", {"form": form})

    user_code: str = form.cleaned_data["user_code"]
    device: Device = get_device_model().objects.get(user_code=user_code)

    if device is None:
        form.add_error("user_code", "Incorrect user code")
        return render(request, "oauth2_provider/device/user_code.html", {"form": form})

    if device.is_expired():
        device.status = device.EXPIRED
        device.save(update_fields=["status"])
        raise ExpiredTokenError

    # User of device has already made their decision for this device
    if device.status in (device.DENIED, device.AUTHORIZED):
        raise AccessDenied

    # 308 to indicate we want to keep the redirect being a POST request
    return http.HttpResponsePermanentRedirect(
        reverse("oauth2_provider:device-confirm", kwargs={"device_code": device.device_code}), status=308
    )


@login_required
def device_confirm_view(request: http.HttpRequest, device_code: str):
    device: Device = get_device_model().objects.get(device_code=device_code)

    if device.status in (device.AUTHORIZED, device.DENIED):
        return http.HttpResponse("Invalid")

    action = request.POST.get("action")

    if action == "accept":
        device.status = device.AUTHORIZED
        device.save(update_fields=["status"])
        return http.HttpResponse("approved")
    elif action == "deny":
        device.status = device.DENIED
        device.save(update_fields=["status"])
        return http.HttpResponse("deny")

    return render(request, "oauth2_provider/device/accept_deny.html")
