Signals
=======

Django-oauth-toolkit sends messages to various signals, depending on the action
that has been triggered.

You can easily import signals from ``oauth2_provider.signals`` and attach your
own listeners.

For example:

.. code-block:: python

    from oauth2_provider.signals import app_authorized

    def handle_app_authorized(sender, request, token, **kwargs):
        print('App {} was authorized'.format(token.application.name))

    app_authorized.connect(handle_app_authorized)

Currently supported signals are:

* ``oauth2_provider.signals.app_authorized`` - fired once an oauth code has been
  authorized and an access token has been granted
