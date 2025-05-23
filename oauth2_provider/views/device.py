import json

from django import forms, http
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from oauthlib.oauth2 import DeviceApplicationServer

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


@login_required
def device_user_code_view(request):
    """
    The view where the user is instructed (by the device) to come to in order to
    enter the user code. More details in this section of the RFC:
    https://datatracker.ietf.org/doc/html/rfc8628#section-3.3

    Note: it's common to see in other implementations of this RFC that only ask the
    user to sign in after they input the user code but since the user has to be signed
    in regardless, to approve the device login we're making the decision here, for
    simplicity, to require being logged in up front.
    """
    form = DeviceForm(request.POST)

    if request.method != "POST":
        return render(request, "oauth2_provider/device/user_code.html", {"form": form})

    if not form.is_valid():
        form.add_error(None, "Form invalid")
        return render(request, "oauth2_provider/device/user_code.html", {"form": form}, status=400)

    user_code: str = form.cleaned_data["user_code"]
    try:
        device: Device = get_device_model().objects.get(user_code=user_code)
    except Device.DoesNotExist:
        form.add_error("user_code", "Incorrect user code")
        return render(request, "oauth2_provider/device/user_code.html", {"form": form}, status=404)

    device.user = request.user
    device.save(update_fields=["user"])

    if device.is_expired():
        form.add_error("user_code", "Expired user code")
        return render(request, "oauth2_provider/device/user_code.html", {"form": form}, status=400)

    # User of device has already made their decision for this device
    if device.status != device.AUTHORIZATION_PENDING:
        form.add_error("user_code", "User code has already been used")
        return render(request, "oauth2_provider/device/user_code.html", {"form": form}, status=400)

    # 308 to indicate we want to keep the redirect being a POST request
    return http.HttpResponsePermanentRedirect(
        reverse(
            "oauth2_provider:device-confirm",
            kwargs={"client_id": device.client_id, "user_code": user_code},
        ),
        status=308,
    )


@login_required
def device_confirm_view(request: http.HttpRequest, client_id: str, user_code: str):
    try:
        device: Device = get_device_model().objects.get(
            # there is a db index on client_id
            Q(client_id=client_id) & Q(user_code=user_code)
        )
    except Device.DoesNotExist:
        return http.HttpResponseNotFound("<h1>Device not found</h1>")

    if device.status != device.AUTHORIZATION_PENDING:
        # AUTHORIZATION_PENDING is the only accepted state, anything else implies
        # that the user already approved/denied OR the deadline has passed (aka
        # expired)
        return http.HttpResponseBadRequest("Invalid")

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
