Installation
============

Install with pip::

    pip install django-oauth-toolkit

Add ``oauth2_provider`` to your ``INSTALLED_APPS``

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'oauth2_provider',
    )


If you need an OAuth2 provider you'll want to add the following to your :file:`urls.py`

.. code-block:: python

    from django.urls import include, path
    from oauth2_provider import urls as oauth2_urls

    urlpatterns = [
        ...
        path('o/', include(oauth2_urls)),
    ]

Sync your database
------------------

.. sourcecode:: sh

    python manage.py migrate oauth2_provider

Next step is :doc:`getting started <getting_started>` or :doc:`first tutorial <tutorial/tutorial_01>`.
