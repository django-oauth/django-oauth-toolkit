from django.urls import include, path

from oauth2_provider import urls as oauth2_urls
from oauth2_provider.urls import metadata_urlpatterns


# The documented deployment for an issuer under a path (https://host/o): the
# strict RFC 8414 well-known routes at the domain root, plus the full toolkit
# (including OIDC discovery and the pragmatic fallback metadata routes) under
# the "/o/" prefix. The root include gets a distinct instance namespace so
# reverse("oauth2_provider:...") for the endpoints resolves unambiguously to
# the "/o/" mount.
urlpatterns = [
    path("", include((metadata_urlpatterns, "oauth2_provider"), namespace="oauth2_metadata")),
    path("o/", include(oauth2_urls)),
]
