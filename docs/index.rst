.. Django OAuth Toolkit documentation master file, created by
   sphinx-quickstart on Mon May 20 19:40:43 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Django OAuth Toolkit Documentation
=============================================

Django OAuth Toolkit can help you by providing, out of the box, all the endpoints, data, and logic needed to add OAuth2
capabilities to your Django projects. Django OAuth Toolkit makes extensive use of the excellent
`OAuthLib <https://github.com/idan/oauthlib>`_, so that everything is
`rfc-compliant <https://rfc-editor.org/rfc/rfc6749.html>`_.

See our :doc:`Changelog <changelog>` for information on updates.

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
   :caption: Getting started

   install
   getting_started
   tutorial/tutorial
   rest-framework/rest-framework
   ninja

.. toctree::
   :maxdepth: 2
   :caption: Using the toolkit

   views/views
   views/details
   templates
   models
   signals
   management_commands
   advanced_topics
   security

.. toctree::
   :maxdepth: 2
   :caption: Authorization Server

   oauth2_server_metadata
   cimd
   oidc

.. toctree::
   :maxdepth: 2
   :caption: Resource Server

   resource_server
   protected_resource_metadata

.. toctree::
   :maxdepth: 2
   :caption: Reference

   settings
   glossary

.. toctree::
   :maxdepth: 1
   :caption: Project

   contributing
   changelog


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
