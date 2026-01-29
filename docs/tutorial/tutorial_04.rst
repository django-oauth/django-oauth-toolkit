Part 4 - Revoking an OAuth2 Token
=================================

Scenario
--------
You've granted a user an :term:`Access Token`, following :doc:`part 1 <tutorial_01>` and now you would like to revoke that token, probably in response to a client request (to logout).

Revoking a Token
----------------
Be sure that you've granted a valid token. If you've hooked in ``oauth-toolkit`` into your :file:`urls.py` as specified in :doc:`part 1 <tutorial_01>`, you'll have a URL at ``/o/revoke_token``. By submitting the appropriate request to that URL, you can revoke a user's :term:`Access Token`.

`Oauthlib <https://github.com/idan/oauthlib>`_ is compliant with https://rfc-editor.org/rfc/rfc7009.html, so as specified, the revocation request requires:

- ``token``:  REQUIRED, this is the :term:`Access Token` you want to revoke
- ``token_type_hint``: OPTIONAL, designating either 'access_token' or 'refresh_token'.

Note that these revocation-specific parameters are in addition to the authentication parameters already specified by your particular client type.

Setup a Request
---------------
Depending on the client type you're using, the token revocation request you may submit to the authentication server may vary. A `Public` client, for example, will not have access to your `Client Secret`. A revoke request from a public client would omit that secret, and take the form:

::

    POST /o/revoke_token/ HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    token=XXXX&client_id=XXXX

Where token is :term:`Access Token` specified above, and client_id is the `Client id` obtained in
obtained in :doc:`part 1 <tutorial_01>`. If your application type is `Confidential` , it requires a `Client secret`, you will have to add it as one of the parameters:

::

    POST /o/revoke_token/ HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    token=XXXX&client_id=XXXX&client_secret=XXXX


The server will respond with a ``200`` status code on successful revocation. You can use ``curl`` to make a revoke request on your server. If you have access to a local installation of your authorization server, you can test revoking a token with a request like that shown below, for a `Confidential` client.

::

    curl --data "token=XXXX&client_id=XXXX&client_secret=XXXX" http://localhost:8000/o/revoke_token/


