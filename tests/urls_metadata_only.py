from django.urls import include, path

from oauth2_provider.urls import metadata_urlpatterns


# Only the RFC 8414 metadata endpoint is registered here — none of the
# authorization/token/revocation/introspection routes exist. Used to exercise
# the metadata view's graceful handling of endpoints that cannot be reversed.
urlpatterns = [
    path("", include((metadata_urlpatterns, "oauth2_provider"))),
]
