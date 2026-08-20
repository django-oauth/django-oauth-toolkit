"""Tests for the templates and static assets shipped with the toolkit.

The built-in pages must render without pulling assets from a third-party host and
without inline styles, so they work in air-gapped installs and under a strict
Content Security Policy (see issue #730).
"""

import re

import pytest
from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.template.loader import render_to_string
from django.urls import reverse

from .common_testing import OAuth2ProviderTestCase as TestCase


UserModel = get_user_model()

STYLESHEET = "oauth2_provider/css/oauth2_provider.css"

# Any src/href pointing at another host: an absolute URL, or a protocol-relative one
# such as the ``//netdna.bootstrapcdn.com/...`` link the base template used to carry.
EXTERNAL_ASSET_RE = re.compile(r"""(?:href|src)\s*=\s*["'](?:[a-z][a-z0-9+.-]*:)?//""", re.IGNORECASE)


class TestBaseTemplate(TestCase):
    def test_stylesheet_is_served_from_static_files(self):
        html = render_to_string("oauth2_provider/base.html")
        self.assertIn(f"/static/{STYLESHEET}", html)

    def test_no_external_assets(self):
        html = render_to_string("oauth2_provider/base.html")
        self.assertIsNone(EXTERNAL_ASSET_RE.search(html))

    def test_no_inline_style_block(self):
        # An inline <style> is blocked by ``style-src 'self'`` just like a foreign
        # style host is, so the default styles must live in the static file.
        html = render_to_string("oauth2_provider/base.html")
        self.assertNotIn("<style", html)

    def test_stylesheet_is_findable_by_staticfiles(self):
        self.assertIsNotNone(finders.find(STYLESHEET))

    def test_css_block_can_be_overridden(self):
        # Projects replace the default styles through the ``css`` block; keep that
        # documented extension point working.
        from django.template import Context, Template

        html = Template(
            '{% extends "oauth2_provider/base.html" %}{% block css %}<link href="/mine.css">{% endblock %}'
        ).render(Context({}))
        self.assertIn("/mine.css", html)
        self.assertNotIn(STYLESHEET, html)


@pytest.mark.usefixtures("oauth2_settings")
class TestRenderedViews(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("foo_user", "test@example.com", "123456")

    def test_application_list_uses_local_stylesheet(self):
        self.client.login(username="foo_user", password="123456")

        response = self.client.get(reverse("oauth2_provider:list"))

        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertIn(f"/static/{STYLESHEET}", html)
        self.assertIsNone(EXTERNAL_ASSET_RE.search(html))
