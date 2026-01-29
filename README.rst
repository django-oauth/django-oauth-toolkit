Django OAuth Toolkit
====================

*OAuth2 goodies for the Djangonauts!*

.. image:: https://badge.fury.io/py/django-oauth-toolkit.svg
    :target: http://badge.fury.io/py/django-oauth-toolkit

.. image:: https://github.com/django-oauth/django-oauth-toolkit/workflows/Test/badge.svg
   :target: https://github.com/django-oauth/django-oauth-toolkit/actions
   :alt: GitHub Actions

.. image:: https://codecov.io/gh/django-oauth/django-oauth-toolkit/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/django-oauth/django-oauth-toolkit
   :alt: Coverage

.. image:: https://img.shields.io/pypi/pyversions/django-oauth-toolkit.svg
   :target: https://pypi.org/project/django-oauth-toolkit/
   :alt: Supported Python versions

.. image:: https://img.shields.io/pypi/djversions/django-oauth-toolkit.svg
   :target: https://pypi.org/project/django-oauth-toolkit/
   :alt: Supported Django versions

If you are facing one or more of the following:
 * Your Django app exposes a web API you want to protect with OAuth2 authentication,
 * You need to implement an OAuth2 authorization server to provide tokens management for your infrastructure,

Django OAuth Toolkit can help you providing out of the box all the endpoints, data and logic needed to add OAuth2
capabilities to your Django projects. Django OAuth Toolkit makes extensive use of the excellent
`OAuthLib <https://github.com/idan/oauthlib>`_, so that everything is
`rfc-compliant <https://rfc-editor.org/rfc/rfc6749.html>`_.

Reporting security issues
-------------------------

Please report any security issues to the Django OAuth security team at <django-oauth-security@googlegroups.com>. Do not file an issue on the tracker.

Requirements
------------

* Python 3.8, 3.9, 3.10, 3.11, 3.12, 3.13 or 3.14
* Django 4.2, 5.0, 5.1 or 5.2
* oauthlib 3.2.2+

Installation
------------

Install with pip::

    pip install django-oauth-toolkit

Add ``oauth2_provider`` to your ``INSTALLED_APPS``

.. code-block:: python

    INSTALLED_APPS = (
        ...
        'oauth2_provider',
    )


If you need an OAuth2 provider you'll want to add the following to your ``urls.py``.

.. code-block:: python

    from oauth2_provider import urls as oauth2_urls

    urlpatterns = [
        ...
        path('o/', include(oauth2_urls)),
    ]

Changelog
---------

See `CHANGELOG.md <https://github.com/django-oauth/django-oauth-toolkit/blob/master/CHANGELOG.md>`_.


Documentation
--------------

The `full documentation <https://django-oauth-toolkit.readthedocs.io/>`_ is on *Read the Docs*.

License
-------

django-oauth-toolkit is released under the terms of the **BSD license**. Full details in ``LICENSE`` file.

Help Wanted
-----------

We need help maintaining and enhancing django-oauth-toolkit (DOT).

Join the team
~~~~~~~~~~~~~

There are no barriers to participation. Anyone can open an issue, pr, or review a pull request. Please
dive in!

How you can help
~~~~~~~~~~~~~~~~

See our
`contributing <https://django-oauth-toolkit.readthedocs.io/en/latest/contributing.html>`__
info and the open
`issues <https://github.com/django-oauth/django-oauth-toolkit/issues>`__ and
`PRs <https://github.com/django-oauth/django-oauth-toolkit/pulls>`__,
especially those labeled
`help-wanted <https://github.com/django-oauth/django-oauth-toolkit/labels/help-wanted>`__.

Discussions
~~~~~~~~~~~
Have questions or want to discuss the project?
See `the discussions <https://github.com/django-oauth/django-oauth-toolkit/discussions>`__.


Submit PRs and Perform Reviews
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PR submissions and reviews are always appreciated! Since we require an
independent review of any PR before it can be merged, having your second
set of eyes looking at PRs is extremely valuable.


Become a Maintainer
~~~~~~~~~~~~~~~~~~~~~

If you are interested in stepping up to be a Maintainer, please open an issue. For maintainers we're
looking for a positive attitude, attentiveness to the specifications, strong coding and
communication skills, and a willingness to work with others. Maintainers are responsible for
merging pull requests, managing issues, creating releases, and ensuring the overall health of the
project.
