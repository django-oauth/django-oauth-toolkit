import pytest
from django.core.validators import ValidationError

from oauth2_provider.validators import AllowedURIValidator

from .common_testing import OAuth2ProviderTestCase as TestCase


@pytest.mark.usefixtures("oauth2_settings")
class TestAllowedURIValidator(TestCase):
    # TODO: verify the specifics of the ValidationErrors
    def test_valid_schemes(self):
        validator = AllowedURIValidator(["my-scheme", "https", "git+ssh"], "test")
        good_uris = [
            "my-scheme://example.com",
            "my-scheme://example",
            "my-scheme://localhost",
            "https://example.com",
            "HTTPS://example.com",
            "git+ssh://example.com",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_invalid_schemes(self):
        validator = AllowedURIValidator(["https"], "test")
        bad_uris = [
            "http:/example.com",
            "HTTP://localhost",
            "HTTP://example.com",
            "https://-exa",  # triggers an exception in the upstream validators
            "HTTP://example.com/path",
            "HTTP://example.com/path?query=string",
            "HTTP://example.com/path?query=string#fragmemt",
            "HTTP://example.com.",
            "http://example.com/path/#fragment",
            "http://example.com?query=string#fragment",
            "123://example.com",
            "http://fe80::1",
            "git+ssh://example.com",
            "my-scheme://example.com",
            "uri-without-a-scheme",
            "https://example.com/#fragment",
            "good://example.com/#fragment",
            "    ",
            "",
            # Bad IPv6 URL, urlparse behaves differently for these
            'https://["><script>alert()</script>',
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_allow_paths_valid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_path=True)
        good_uris = [
            "https://example.com",
            "https://example.com:8080",
            "https://example",
            "https://example.com/path",
            "https://example.com:8080/path",
            "https://example/path",
            "https://localhost/path",
            "myapp://host/path",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_bare_fragment_delimiter_rejected(self):
        # A trailing "#" is an empty fragment component, which RFC 6749 §3.1.2
        # forbids just as much as a populated one. urlsplit() reports fragment ==
        # "" for it, so the raw string is what has to be checked -- otherwise it
        # is stored and then never matches, since redirect_to_uri_allowed()
        # denies any URI containing "#".
        validator = AllowedURIValidator(["https"], "test", allow_path=True)
        for uri in ["https://example.com/cb#", "https://example.com/cb#frag"]:
            with self.assertRaises(ValidationError):
                validator(uri)

        # A percent-encoded %23 is not a fragment delimiter and stays valid.
        validator("https://example.com/cb%23")

        # ...and where fragments are allowed, both forms still pass.
        permissive = AllowedURIValidator(["https"], "test", allow_path=True, allow_fragments=True)
        permissive("https://example.com/cb#")
        permissive("https://example.com/cb#frag")

    def test_bare_query_delimiter_rejected(self):
        # Same shape as the bare "#" above: urlsplit() reports query == "" for a
        # URI ending in "?", so it slipped past the allow_query=False gate that
        # allowed_origins relies on.
        validator = AllowedURIValidator(["https"], "test")
        for uri in ["https://example.com?", "https://example.com?a=1"]:
            with self.assertRaises(ValidationError):
                validator(uri)

        # A "?" inside a fragment belongs to the fragment and does not open a
        # query component, so it must not trip the allow_query=False gate. With
        # fragments permitted there is nothing left to reject, and the URI passes.
        fragments_ok = AllowedURIValidator(["https"], "test", allow_fragments=True)
        fragments_ok("https://example.com#a?b")

        # ...and where queries are allowed, both forms still pass.
        permissive = AllowedURIValidator(["https"], "test", allow_query=True)
        permissive("https://example.com?")
        permissive("https://example.com?a=1")

    def test_allow_paths_invalid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_path=True)
        bad_uris = [
            "https://example.com?query=string",
            "https://example.com#fragment",
            "https://example.com/path?query=string",
            "https://example.com/path#fragment",
            "https://example.com/path?query=string#fragment",
            "myapp://example.com/path?query=string",
            "myapp://example.com/path#fragment",
            "myapp://example.com/path?query=string#fragment",
            "bad://example.com/path",
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_allow_query_valid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_query=True)
        good_uris = [
            "https://example.com",
            "https://example.com:8080",
            "https://example.com?query=string",
            "https://example",
            "myapp://example.com?query=string",
            "myapp://example?query=string",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_allow_query_invalid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_query=True)
        bad_uris = [
            "https://example.com/path",
            "https://example.com#fragment",
            "https://example.com/path?query=string",
            "https://example.com/path#fragment",
            "https://example.com/path?query=string#fragment",
            "https://example.com:8080/path",
            "https://example/path",
            "https://localhost/path",
            "myapp://example.com/path?query=string",
            "myapp://example.com/path#fragment",
            "myapp://example.com/path?query=string#fragment",
            "bad://example.com/path",
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_allow_fragment_valid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_fragments=True)
        good_uris = [
            "https://example.com",
            "https://example.com#fragment",
            "https://example.com:8080",
            "https://example.com:8080#fragment",
            "https://example",
            "https://example#fragment",
            "myapp://example",
            "myapp://example#fragment",
            "myapp://example.com",
            "myapp://example.com#fragment",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_allow_fragment_invalid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_fragments=True)
        bad_uris = [
            "https://example.com?query=string",
            "https://example.com?query=string#fragment",
            "https://example.com/path",
            "https://example.com/path?query=string",
            "https://example.com/path#fragment",
            "https://example.com/path?query=string#fragment",
            "https://example.com:8080/path",
            "https://example?query=string",
            "https://example?query=string#fragment",
            "https://example/path",
            "https://example/path?query=string",
            "https://example/path#fragment",
            "https://example/path?query=string#fragment",
            "myapp://example?query=string",
            "myapp://example?query=string#fragment",
            "myapp://example/path",
            "myapp://example/path?query=string",
            "myapp://example/path#fragment",
            "myapp://example.com/path?query=string",
            "myapp://example.com/path#fragment",
            "myapp://example.com/path?query=string#fragment",
            "myapp://example.com?query=string",
            "bad://example.com",
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_allow_hostname_wildcard(self):
        validator = AllowedURIValidator(["https"], "test", allow_hostname_wildcard=True)
        good_uris = [
            "https://*.example.com",
            "https://*-partial.example.com",
            "https://*.partial.example.com",
            "https://*-partial.valid.example.com",
            # Netlify deploy-preview hostnames use a double dash, e.g.
            # deploy-preview-42--sitename.netlify.app, so the corresponding
            # wildcard has two leading dashes after the "*". See issue #1619.
            "https://*--sitename.netlify.app",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

        bad_uris = [
            "https://*/",
            "https://*-partial",
            "https://*.com",
            "https://*-partial.com",
            "https://*---sitename.netlify.app",
            "https://*.*.example.com",
            "https://invalid.*.example.com",
        ]
        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)


@pytest.mark.usefixtures("oauth2_settings")
class TestPrivateUseURISchemeValidator(TestCase):
    """
    RFC 8252 §7.1 private-use URI scheme redirects have no naming authority
    (RFC 3986 §3.2), so only a single slash follows the scheme component.
    """

    def test_valid_private_use_uris(self):
        validator = AllowedURIValidator(["com.example.app", "myapp"], "test", allow_path=True)
        good_uris = [
            # The complete example given in RFC 8252 §7.1.
            "com.example.app:/oauth2redirect/example-provider",
            "com.example.app:/oauth2redirect",
            "com.example.app:/",
            "myapp:/callback",
            # urlsplit() lowercases the scheme, so matching is case-insensitive.
            "COM.EXAMPLE.APP:/oauth2redirect",
            # The double-slash spelling remains valid; it is simply a different
            # URI, parsing to a hostname rather than to no authority at all.
            "com.example.app://oauth2redirect",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_valid_private_use_uri_with_query(self):
        validator = AllowedURIValidator(["com.example.app"], "test", allow_path=True, allow_query=True)
        validator("com.example.app:/oauth2redirect?state=xyz")

    def test_invalid_private_use_uris(self):
        validator = AllowedURIValidator(["com.example.app", "myapp"], "test", allow_path=True)
        bad_uris = [
            # No callback target at all.
            "com.example.app:",
            "com.example.app://",
            # Valid absolute-URIs per RFC 3986 §4.3, but rejected as
            # non-canonical: "scheme:///path" aliases with the single-slash form
            # under redirect_to_uri_allowed(), and RFC 9700 §2.1 requires exact
            # string matching.  "scheme:path" (path-rootless) is not the shape
            # RFC 8252 §7.1 prescribes.
            "com.example.app:///oauth2redirect",
            "com.example.app:oauth2redirect",
            # Whitespace is never part of a redirect URI.
            "com.example.app:/oauth2 redirect",
            # Scheme still has to be allowed.
            "com.other.app:/oauth2redirect",
        ]
        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_schemes_requiring_an_authority_still_require_a_host(self):
        # "https:/example.com" is a valid absolute-URI, but browsers normalize it
        # to "https://example.com/", so registering it would not describe what is
        # actually redirected to.  Only non-special schemes may omit the authority.
        validator = AllowedURIValidator(["https", "http", "ws", "wss", "ftp"], "test", allow_path=True)
        for uri in ["https:/example.com", "http:/example.com", "ws:/x", "wss:/x", "ftp:/x"]:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_private_use_uri_rejected_when_paths_are_not_allowed(self):
        # allowed_origins uses allow_path=False, so a private-use redirect URI is
        # still rejected there — an origin has no path and needs a host.
        validator = AllowedURIValidator(["com.example.app"], "test")
        with self.assertRaises(ValidationError):
            validator("com.example.app:/oauth2redirect")
