.. Django OAuth Toolkit documentation master file, created by
   sphinx-quickstart on Mon May 20 19:40:43 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Django OAuth Toolkit Documentation
=============================================

Django OAuth Toolkit is an OAuth 2.0 authorization server for teams already running Django. It
provides, out of the box, the endpoints, models, and logic to issue and manage OAuth2 tokens from
your existing Django project. It can also act as a resource server to protect a Django or Django
REST Framework API. Django OAuth Toolkit makes extensive use of the excellent
`OAuthLib <https://github.com/idan/oauthlib>`_, so that everything is
`rfc-compliant <https://rfc-editor.org/rfc/rfc6749.html>`_.

See our :doc:`Changelog <changelog>` for information on updates.

MCP authorization
-----------------

As of 3.4.0, Django OAuth Toolkit supports the authorization server role required by the Model
Context Protocol (MCP) authorization specification. PKCE is required by default, and the
:doc:`authorization server metadata <oauth2_server_metadata>` (RFC 8414) and
:doc:`protected resource metadata <protected_resource_metadata>` (RFC 9728) discovery endpoints are
included in the default URLconf. :doc:`Dynamic Client Registration </views/dynamic_client_registration>`
(RFC 7591/7592) and :doc:`Client ID Metadata Documents <cimd>` can be enabled with the ``DCR_ENABLED``
and ``CIMD_ENABLED`` settings. See the
`3.4.0 release discussion <https://github.com/django-oauth/django-oauth-toolkit/discussions/1775>`_
for the supported specifications and current gaps.

Support
-------

If you need help please submit a `question <https://github.com/django-oauth/django-oauth-toolkit/issues/new?assignees=&labels=question&template=question.md&title=>`_.

Requirements
------------

* Python 3.10, 3.11, 3.12, 3.13 or 3.14
* Django 4.2, 5.0, 5.1, 5.2 or 6.0
* oauthlib 3.2.2+

Index
=====

.. toctree::
   :maxdepth: 2

   install
   getting_started
   tutorial/tutorial
   rest-framework/rest-framework
   ninja
   views/views
   templates
   views/details
   models
   advanced_topics
   security
   oidc
   oauth2_server_metadata
   protected_resource_metadata
   cimd
   signals
   settings
   resource_server
   management_commands
   glossary

.. toctree::
   :maxdepth: 1

   contributing
   changelog


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
