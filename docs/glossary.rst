Glossary
========

.. Put definition of specific terms here, and reference them inside docs with :term:`My term` syntax

.. glossary::

    Authorization Server
        The authorization server asks resource owners for their consensus to let client applications access their data.
        It also manages and issues the tokens needed for all the authorization flows supported by OAuth2 spec.
        Usually the same application offering resources through an OAuth2-protected API also behaves like an
        authorization server.

    Resource Server
        An application providing access to its own resources through an API protected following the OAuth2 spec.

    Application
        An Application represents a Client on the Authorization server. Usually an Application is
        created manually by client's developers after logging in on an Authorization Server.

    Client
        A client is an application authorized to access OAuth2-protected resources on behalf and with the authorization
        of the resource owner.

    Resource Owner
        The user of an application which exposes resources to third party applications through OAuth2. The
        resource owner must give her authorization for third party applications to be able to access her data.

    Access Token
        A token needed to access resources protected by OAuth2. It has a lifetime which is usually quite short.

    Authorization Code
        The authorization code is obtained by using an authorization server as an intermediary between the client and
        resource owner. It is used to authenticate the client and grant the transmission of the Access Token.

    Authorization Token
        A token the authorization server issues to clients that can be swapped for an access token. It has a very short
        lifetime since the swap has to be performed shortly after users provide their authorization.

    Refresh Token
        A token the authorization server may issue to clients and can be swapped for a brand new access token, without
        repeating the authorization process. It has no expire time.
