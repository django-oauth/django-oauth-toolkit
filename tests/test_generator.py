import pytest

from oauth2_provider.generators import BaseHashGenerator, generate_client_id, generate_client_secret

from .common_testing import OAuth2ProviderTestCase as TestCase


class MockHashGenerator(BaseHashGenerator):
    def hash(self):
        return 42


@pytest.mark.usefixtures("oauth2_settings")
class TestGenerators(TestCase):
    def test_generate_client_id(self):
        g = self.oauth2_settings.CLIENT_ID_GENERATOR_CLASS()
        self.assertEqual(len(g.hash()), 40)

        self.oauth2_settings.CLIENT_ID_GENERATOR_CLASS = MockHashGenerator
        self.assertEqual(generate_client_id(), 42)

    def test_generate_secret_id(self):
        g = self.oauth2_settings.CLIENT_SECRET_GENERATOR_CLASS()
        self.assertEqual(len(g.hash()), 128)

        self.oauth2_settings.CLIENT_SECRET_GENERATOR_CLASS = MockHashGenerator
        self.assertEqual(generate_client_secret(), 42)

    def test_basegen_misuse(self):
        g = BaseHashGenerator()
        self.assertRaises(NotImplementedError, g.hash)
