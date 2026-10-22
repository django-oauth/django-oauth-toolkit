"""Relying-party / OAuth client helpers.

Everything else in this package implements the *provider* side — the
authorization server, its OpenID Connect Provider facet, and the resource
server. This package is the other side of the wire: helpers a **client** uses
when talking to some authorization server, which may well not be this one.

It is deliberately small and standalone. Nothing here imports from
``oauth2_provider.authorization_server``; it does not touch the app registry or
any model, so it can be used from a plain client application. Django OAuth
Toolkit's own resource server imports from here when it authenticates to a
remote authorization server's introspection endpoint — in that exchange the
resource server *is* an OAuth client.

Currently: RFC 7523 client authentication assertions
(:func:`oauth2_provider.client.client_assertions.make_client_assertion`) and
RFC 7523 §2.1 JWT bearer grant assertions
(:func:`oauth2_provider.client.rfc7523.build_jwt_bearer_assertion`).
"""

from oauth2_provider.client.client_assertions import make_client_assertion
from oauth2_provider.client.rfc7523 import build_jwt_bearer_assertion


__all__ = ["make_client_assertion", "build_jwt_bearer_assertion"]
