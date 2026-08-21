"""Root URL aggregator for Django OAuth Toolkit.

The URL patterns are defined in role modules and aggregated here under the
``oauth2_provider`` URL namespace:

* :mod:`oauth2_provider.authorization_server.urls`
  (``server_metadata_urlpatterns``, ``base_urlpatterns``,
  ``management_urlpatterns``, ``dcr_urlpatterns``),
* :mod:`oauth2_provider.authorization_server.oidc.urls` (``oidc_urlpatterns``),
* :mod:`oauth2_provider.resource_server.urls` (``resource_metadata_urlpatterns``).

Include this module (``include("oauth2_provider.urls")``) as before; the public
``*_urlpatterns`` names below are preserved for callers that mount subsets
separately.
"""

from oauth2_provider.authorization_server.oidc.urls import oidc_urlpatterns
from oauth2_provider.authorization_server.urls import (
    base_urlpatterns,
    dcr_urlpatterns,
    management_urlpatterns,
    server_metadata_urlpatterns,
)
from oauth2_provider.resource_server.urls import resource_metadata_urlpatterns


app_name = "oauth2_provider"

# Back-compat: ``metadata_urlpatterns`` historically bundled both the RFC 8414
# authorization-server well-known routes and the RFC 9728 protected-resource
# well-known routes. It is kept here (combined) so existing deployments that mount
# it separately at the server root keep working — see
# docs/oauth2_server_metadata.rst and docs/protected_resource_metadata.rst.
metadata_urlpatterns = server_metadata_urlpatterns + resource_metadata_urlpatterns

# The default urlpatterns include metadata_urlpatterns so that a root include
# (path("", include("oauth2_provider.urls"))) publishes the RFC 8414 well-known
# endpoint out of the box. Mounted under a prefix (e.g. path("o/", include(...)))
# these routes serve the issuer + /.well-known/oauth-authorization-server
# fallback form that some clients use; strict RFC 8414 clients look for the
# well-known URI at the domain root with the issuer path appended, so prefixed
# deployments should ALSO mount metadata_urlpatterns separately at the server
# root — see docs/oauth2_server_metadata.rst.
urlpatterns = (
    metadata_urlpatterns + base_urlpatterns + management_urlpatterns + oidc_urlpatterns + dcr_urlpatterns
)
