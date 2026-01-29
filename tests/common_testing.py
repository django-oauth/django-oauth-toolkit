from django.conf import settings
from django.test import TestCase as DjangoTestCase
from django.test import TransactionTestCase as DjangoTransactionTestCase


# The multiple database scenario setup for these tests purposefully defines 'default' as
# an empty database in order to catch any assumptions in this package about database names
# and in particular to ensure there is no assumption that 'default' is a valid database.
#
# When there are multiple databases defined, Django tests will not work unless they are
# told which database(s) to work with.


def retrieve_current_databases():
    if len(settings.DATABASES) > 1:
        return [name for name in settings.DATABASES if name != "default"]
    else:
        return ["default"]


class OAuth2ProviderBase:
    @classmethod
    def setUpClass(cls):
        cls.databases = retrieve_current_databases()
        super().setUpClass()


class OAuth2ProviderTestCase(OAuth2ProviderBase, DjangoTestCase):
    """Place holder to allow overriding behaviors."""


class OAuth2ProviderTransactionTestCase(OAuth2ProviderBase, DjangoTransactionTestCase):
    """Place holder to allow overriding behaviors."""
