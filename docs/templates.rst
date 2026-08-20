Templates
=========

A set of templates is provided. These templates range from Django Admin Site alternatives to manage the Apps that use your App as a provider, to Error and Authorization Templates.

You can override default templates located in ``templates/oauth2_provider`` folder and provide a custom layout.
To override these templates you just need to create a folder named ``oauth2_provider`` inside your templates folder and, inside this folder, add a file that matches the name of the template you're trying to override.

.. important:

    In ``INSTALLED_APPS`` on ``settings.py``, ``'django.contrib.staticfiles'``, must be before ``'oauth2_provider'``.

.. note:

    Every view provides access only to data belonging to the logged in user who performs the request.

The templates available are:

- `base.html`_
- `authorize.html`_
- `Management`_:
    - `Application`_:
        - `application_list.html`_
        - `application_form.html`_
        - `application_registration_form.html`_
        - `application_detail.html`_
        - `application_confirm_delete.html`_
    - `Token`_:
        - `authorized-tokens.html`_
        - `authorized-token-delete.html`_



base.html
---------

If you just want a different look and feel you may only override this template.
To inherit this template just add ``{% extends "oauth2_provider/base.html" %}`` in the first line of the other templates. This is what is done with the default templates.

The blocks defined in it are:

- ``title`` inside the HTML title tag;
- ``css`` inside the head;
- ``content`` in the body.

.. note:

    See ` Django docs on template inheritance <https://docs.djangoproject.com/en/dev/ref/templates/language/#template-inheritance>`_ for more information on the use of blocks.

.. _default-stylesheet:

Default stylesheet
~~~~~~~~~~~~~~~~~~

The ``css`` block loads a small stylesheet that ships with the package, from
``static/oauth2_provider/css/oauth2_provider.css``::

    {% block css %}
        <link href="{% static 'oauth2_provider/css/oauth2_provider.css' %}" rel="stylesheet">
    {% endblock css %}

It is served like any other static file, so run ``collectstatic`` (or serve the app's
static files some other way) for the built-in pages to be styled. Because nothing is
fetched from a third-party host and no inline ``<style>`` is used, the shipped pages
render offline and under a strict Content Security Policy such as
``default-src 'self'`` (see :ref:`csp-authorization-form`).

To use your own styles — a CSS framework, or your site's stylesheet — override the
``css`` block::

    {% extends "oauth2_provider/base.html" %}
    {% load static %}

    {% block css %}
        <link href="{% static 'my_project/css/oauth2.css' %}" rel="stylesheet">
    {% endblock css %}

The shipped templates use these class names, which a replacement stylesheet needs to
cover: ``container``, ``block-center``, ``block-center-heading``, ``unstyled``,
``control-group`` (plus ``error``), ``control-label``, ``controls``, ``form-horizontal``,
``input-block-level``, ``help-block``, ``help-inline``, ``btn``, ``btn-large``,
``btn-primary``, ``btn-danger``, ``btn-success`` and ``btn-toolbar``. They are the
Bootstrap 2 names the templates have always used, so a Bootstrap-based override keeps
working.

authorize.html
--------------

Authorize is rendered in :class:`~oauth2_provider.views.base.AuthorizationView` (``authorize/``).

This template gets passed the following context variables:


- ``scopes`` - :obj:`list` with the scopes requested by the application;

.. caution::
    See :ref:`settings_default_scopes` to understand what is returned if no scopes are requested.

- ``scopes_descriptions`` - :obj:`list` with the descriptions for the scopes requested;

- ``application`` - An :class:`~oauth2_provider.models.Application` object

.. note::
    If you haven't created your own Application Model (see how in :ref:`extend_app_model`), you will get an
    :class:`~oauth2_provider.models.AbstractApplication` object.

- ``client_id`` - Passed in the URI, already validated.
- ``redirect_uri`` - Passed in the URI (optional), already validated.

.. note::
    If it wasn't provided on the request, the default one has been set (see :meth:`~oauth2_provider.models.AbstractApplication.default_redirect_uri`).

- ``response_type`` - Passed in the URI, already validated.
- ``state`` - Passed in the URI (optional).
- ``form`` - An :class:`~oauth2_provider.forms.AllowForm` with all the hidden fields already filled with the values above.

.. important::
    One extra variable, named ``error`` will also be available if an Oauth2 exception occurs.
    This variable is a :obj:`dict` with ``error`` and ``description``

Example (this is the default page you may find on ``templates/oauth2_provider/authorize.html``): ::

    {% extends "oauth2_provider/base.html" %}

    {% load i18n %}
    {% block content %}
        <div class="block-center">
            {% if not error %}
                <form id="authorizationForm" method="post">
                    <h3 class="block-center-heading">{% trans "Authorize" %} {{ application.name }}?</h3>
                    {% csrf_token %}

                    {% for field in form %}
                        {% if field.is_hidden %}
                            {{ field }}
                        {% endif %}
                    {% endfor %}

                    <p>{% trans "Application requires the following permissions" %}</p>
                    <ul>
                        {% for scope in scopes_descriptions %}
                            <li>{{ scope }}</li>
                        {% endfor %}
                    </ul>

                    {{ form.errors }}
                    {{ form.non_field_errors }}

                    <div class="control-group">
                        <div class="controls">
                            <input type="submit" class="btn btn-large" value="Cancel"/>
                            <input type="submit" class="btn btn-large btn-primary" name="allow" value="Authorize"/>
                        </div>
                    </div>
                </form>

            {% else %}
                <h2>Error: {{ error.error }}</h2>
                <p>{{ error.description }}</p>
            {% endif %}
        </div>
    {% endblock %}


Management
----------
The management templates are Django Admin Site alternatives to manage the Apps.


Application
```````````
All templates receive :class:`~oauth2_provider.models.Application` objects.

.. note::
    If you haven't created your own Application Model (see how in :ref:`extend_app_model`), you will get an
    :class:`~oauth2_provider.models.AbstractApplication` object.


application_list.html
~~~~~~~~~~~~~~~~~~~~~
Rendered in :class:`~oauth2_provider.views.base.ApplicationList` (``applications/``).
This class inherits :class:`django.views.generic.edit.ListView`.

This template gets passed the following template context variable:

- ``applications`` - a :obj:`list` with all the applications, may be ``None``.


application_form.html
~~~~~~~~~~~~~~~~~~~~~
Rendered in :class:`~oauth2_provider.views.base.ApplicationUpdate` (``applications/<pk>/update/``).
This class inherits :class:`django.views.generic.edit.UpdateView`.

This template gets passed the following template context variables:

- ``application`` - the :class:`~oauth2_provider.models.Application` object.
- ``form`` - a :obj:`~django.forms.Form` with the following fields:
    - ``name``
    - ``client_id``
    - ``client_secret``
    - ``client_type``
    - ``authorization_grant_type``
    - ``redirect_uris``
    - ``post_logout_redirect_uris``

.. caution::
    In the default implementation this template in extended by `application_registration_form.html`_.
    Be sure to provide the same blocks if you are only overriding this template.

.. note::
    Application validation errors are attached to the field they belong to (for example a
    rejected redirect URI to ``redirect_uris``, or a non-https CORS origin to
    ``allowed_origins``), so a custom template should render ``field.errors`` for every
    field as the shipped one does. Keep rendering ``form.non_field_errors`` as well: an
    error for a field the form does not include falls back to a non-field error.

application_registration_form.html
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rendered in :class:`~oauth2_provider.views.base.ApplicationRegistration` (``applications/register/``).
This class inherits :class:`django.views.generic.edit.CreateView`.

This template gets passed the following template context variable:

- ``form`` - a :obj:`~django.forms.Form` with the following fields:
    - ``name``
    - ``client_id``
    - ``client_secret``
    - ``client_type``
    - ``authorization_grant_type``
    - ``redirect_uris``
    - ``post_logout_redirect_uris``

.. note::
    In the default implementation this template extends `application_form.html`_.



application_detail.html
~~~~~~~~~~~~~~~~~~~~~~~
Rendered in :class:`~oauth2_provider.views.base.ApplicationDetail` (``applications/<pk>/``).
This class inherits :class:`django.views.generic.edit.DetailView`.

This template gets passed the following template context variable:

- ``application`` - the :class:`~oauth2_provider.models.Application` object.

application_confirm_delete.html
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rendered in :class:`~oauth2_provider.views.base.ApplicationDelete` (``applications/<pk>/delete/``).
This class inherits :class:`django.views.generic.edit.DeleteView`.

This template gets passed the following template context variable:

- ``application`` - the :class:`~oauth2_provider.models.Application` object.

.. important::
    To override successfully this template you should provide a form that posts to the same URL, example:
    ``<form method="post" action="">``


Token
`````
All templates receive :class:`~oauth2_provider.models.AccessToken` objects.

authorized-tokens.html
~~~~~~~~~~~~~~~~~~~~~~
Rendered in :class:`~oauth2_provider.views.base.AuthorizedTokensListView` (``authorized_tokens/``).
This class inherits :class:`django.views.generic.edit.ListView`.

This template gets passed the following template context variable:

- ``authorized_tokens`` - a :obj:`list` with all the tokens that belong to applications that the user owns, may be ``None``.

.. important::
    To override successfully this template you should provide links to revoke the token, example:
    ``<a href="{% url 'oauth2_provider:authorized-token-delete' authorized_token.pk %}">revoke</a>``


authorized-token-delete.html
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Rendered in :class:`~oauth2_provider.views.base.AuthorizedTokenDeleteView` (``authorized_tokens/<pk>/delete/``).
This class inherits :class:`django.views.generic.edit.DeleteView`.

This template gets passed the following template context variable:

- ``authorized_token`` - the :class:`~oauth2_provider.models.AccessToken` object.

.. important::
    To override successfully this template you should provide a form that posts to the same URL, example:
    ``<form method="post" action="">``
