import json

from django import http
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from oauthlib.oauth2 import DeviceApplicationServer

from oauth2_provider.compat import login_not_required
from oauth2_provider.models import DeviceCodeResponse, DeviceRequest, create_device
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
