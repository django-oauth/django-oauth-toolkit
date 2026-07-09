"""
URL configuration for idp project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path
from django.views.generic import TemplateView

from oauth2_provider.urls import metadata_urlpatterns
from oauth2_provider.views.generic import ProtectedResourceMetadataView


class DemoProtectedResourceView(ProtectedResourceMetadataView):
    """A minimal RFC 9728 protected resource.

    Requires a valid Bearer token; on failure it returns an RFC 6750 challenge
    whose ``resource_metadata`` parameter points at this server's
    ``/.well-known/oauth-protected-resource`` document.
    """

    def get(self, request, *args, **kwargs):
        return JsonResponse({"protected": True})


urlpatterns = [
    path(
        "", TemplateView.as_view(template_name="home/index.html"), name="home"
    ),  # Maps the root URL to your home_view
    path("admin/", admin.site.urls),
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    path("accounts/", include("django.contrib.auth.urls")),
    # A demo RFC 9728 protected resource for the end-to-end suite.
    path("resource/", DemoProtectedResourceView.as_view(), name="e2e-protected-resource"),
    # RFC 8414 locates the metadata document at the server root. Because the
    # provider is mounted under /o/, strict clients look for it at
    # /.well-known/oauth-authorization-server/o (the issuer path appended). DOT's
    # docs recommend prefixed deployments also expose the metadata at the root,
    # under a distinct instance namespace so reverse() lookups stay unambiguous
    # with the /o/ include above.
    path("", include((metadata_urlpatterns, "oauth2_provider"), namespace="oauth2_provider_metadata")),
]
