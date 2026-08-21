"""Protocol constants shared by the RFC 7523 client-authentication participants.

RFC 7523 client authentication involves all three roles, so the wire constant
lives here rather than in any one role package:

* the **authorization server** checks it on an incoming ``client_assertion_type``
  (:mod:`oauth2_provider.authorization_server.client_assertions`),
* a **client / relying party** sends it alongside the assertion it builds
  (:mod:`oauth2_provider.client.client_assertions`), and
* the **resource server** sends it when authenticating to a remote
  authorization server's introspection endpoint — acting as a client itself
  (:mod:`oauth2_provider.resource_server.validators`).
"""

# RFC 7523 section 2.2 / RFC 7521 section 4.2.
JWT_BEARER_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
