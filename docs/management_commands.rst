Management commands
===================

Django OAuth Toolkit exposes some useful management commands that can be run via shell or by other means such as cron
or :doc:`Celery <tutorial/tutorial_05>`.

.. _cleartokens:

cleartokens
~~~~~~~~~~~

The ``cleartokens`` management command allows the user to remove those refresh tokens whose lifetime is greater than the
amount specified by ``REFRESH_TOKEN_EXPIRE_SECONDS`` settings. It is important that this command is run regularly
(eg: via cron) to avoid cluttering the database with expired refresh tokens.

If ``cleartokens`` runs daily the maximum delay before a refresh token is
removed is ``REFRESH_TOKEN_EXPIRE_SECONDS`` + 1 day. This is normally not a
problem since refresh tokens are long lived.

To prevent the CPU and RAM high peaks during deletion process use ``CLEAR_EXPIRED_TOKENS_BATCH_SIZE`` and
``CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL`` settings to adjust the process speed.

The ``cleartokens`` management command will also delete expired access and ID tokens alongside expired refresh tokens.

Note: Refresh tokens need to expire before AccessTokens can be removed from the
database. Using ``cleartokens`` without ``REFRESH_TOKEN_EXPIRE_SECONDS`` has limited effect.

.. _createapplication:

createapplication
~~~~~~~~~~~~~~~~~

The ``createapplication`` management command provides a shortcut to create a new application in a programmatic way.

.. code-block:: sh

    usage: manage.py createapplication [-h] [--client-id CLIENT_ID] [--user USER]
                                       [--redirect-uris REDIRECT_URIS]
                                       [--post-logout-redirect-uris POST_LOGOUT_REDIRECT_URIS]
                                       [--client-secret CLIENT_SECRET]
                                       [--name NAME] [--skip-authorization]
                                       [--algorithm ALGORITHM] [--version]
                                       [-v {0,1,2,3}] [--settings SETTINGS]
                                       [--pythonpath PYTHONPATH] [--traceback]
                                       [--no-color] [--force-color]
                                       [--skip-checks]
                                       client_type authorization_grant_type

    Shortcut to create a new application in a programmatic way

    positional arguments:
      client_type           The client type, one of: confidential, public
      authorization_grant_type
                            The type of authorization grant to be used, one of:
                            authorization-code, implicit, password, client-
                            credentials, openid-hybrid

    optional arguments:
      -h, --help            show this help message and exit
      --client-id CLIENT_ID
                            The ID of the new application
      --user USER           The user the application belongs to
      --redirect-uris REDIRECT_URIS
                            The redirect URIs, this must be a space separated
                            string e.g 'URI1 URI2'
      --post-logout-redirect-uris POST_LOGOUT_REDIRECT_URIS
                            The post logout redirect URIs, this must be a space
                            separated string e.g 'URI1 URI2'
      --client-secret CLIENT_SECRET
                            The secret for this application
      --name NAME           The name this application
      --skip-authorization  If set, completely bypass the authorization form, even
                            on the first use of the application
      --algorithm ALGORITHM
                            The OIDC token signing algorithm for this application,
                            one of: RS256, HS256
      --version             Show program's version number and exit.
      -v {0,1,2,3}, --verbosity {0,1,2,3}
                            Verbosity level; 0=minimal output, 1=normal output,
                            2=verbose output, 3=very verbose output
      --settings SETTINGS   The Python path to a settings module, e.g.
                            "myproject.settings.main". If this isn't provided, the
                            DJANGO_SETTINGS_MODULE environment variable will be
                            used.
      --pythonpath PYTHONPATH
                            A directory to add to the Python path, e.g.
                            "/home/djangoprojects/myproject".
      --traceback           Raise on CommandError exceptions.
      --no-color            Don't colorize the command output.
      --force-color         Force colorization of the command output.
      --skip-checks         Skip system checks.

If you let ``createapplication`` auto-generate the secret then it displays the value before hashing it.

