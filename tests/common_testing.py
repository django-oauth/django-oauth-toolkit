from django.test import TestCase as DjangoTestCase
from django.test import TransactionTestCase as DjangoTransactionTestCase


class OAuth2ProviderBase:
    # ``databases`` must be a class attribute so pytest-django can grant access during
    # database setup, before class setup hooks run.
    databases = "__all__"


class OAuth2ProviderTestCase(OAuth2ProviderBase, DjangoTestCase):
    """Place holder to allow overriding behaviors."""


class OAuth2ProviderTransactionTestCase(OAuth2ProviderBase, DjangoTransactionTestCase):
    """Place holder to allow overriding behaviors."""
