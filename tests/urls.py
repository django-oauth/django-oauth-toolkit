from django.contrib import admin
from django.urls import include, path

from oauth2_provider import urls as oauth2_urls


admin.autodiscover()


urlpatterns = [
    path("o/", include(oauth2_urls)),
    path("admin/", admin.site.urls),
]
