Granted Tokens Views
====================

A set of views is provided to let users handle tokens that have been granted to them, without needing to accessing Django Admin Site.
Every view provides access only to the tokens that have been granted to the user performing the request.


Granted Token views are listed at the url ``authorized_tokens/``.


For each granted token there is a delete view that allows you to delete such token. You can override default templates :file:`authorized-tokens.html` for the list view and :file:`authorized-token-delete.html` for the delete view; they are located inside :file:`templates/oauth2_provider` folder.


.. automodule:: oauth2_provider.views.token
    :members:
