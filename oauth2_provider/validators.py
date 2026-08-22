import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.utils.encoding import force_str


if TYPE_CHECKING:
    # Only for annotations: models.py imports this module at runtime, so importing it
    # back unguarded would be a cycle.
    from .models import AbstractApplication


class URIValidator(URLValidator):
    scheme_re = r"^(?:[a-z][a-z0-9\.\-\+]*)://"

    dotless_domain_re = r"(?!-)[A-Z\d-]{1,63}(?<!-)"
    host_re = "|".join(
        (r"(?:" + URLValidator.host_re, URLValidator.ipv4_re, URLValidator.ipv6_re, dotless_domain_re + ")")
    )
    port_re = r"(?::\d{2,5})?"
    path_re = r"(?:[/?#][^\s]*)?"
    regex = re.compile(scheme_re + host_re + port_re + path_re, re.IGNORECASE)

    # RFC 8252 §7.1: a private-use URI scheme redirect has no naming authority
    # (RFC 3986 §3.2), so exactly one slash follows the scheme component, e.g.
    # "com.example.app:/oauth2redirect".  Requiring a non-slash after "scheme:/"
    # also rejects "scheme:", "scheme://" and the redundant "scheme:///path"
    # spelling; the latter is a valid absolute-URI (an empty authority) but
    # aliases with the canonical single-slash form under redirect_to_uri_allowed(),
    # and RFC 9700 §2.1 requires redirect URIs to match by exact string comparison.
    authorityless_regex = re.compile(r"^[a-z][a-z0-9\.\-\+]*:/(?!/)[^\s]*\Z", re.IGNORECASE)

    # Schemes whose own specifications require an authority component.  A
    # single-slash URI in one of these is not a private-use scheme redirect:
    # browsers normalize "https:/example.com" to "https://example.com/", so
    # accepting it would register something other than what is redirected to.
    schemes_requiring_authority = frozenset({"http", "https", "ws", "wss", "ftp"})


class AllowedURIValidator(URIValidator):
    # TODO: find a way to get these associated with their form fields in place of passing name
    # TODO: submit PR to get `cause` included in the parent class ValidationError params`
    def __init__(
        self,
        schemes,
        name,
        allow_path=False,
        allow_query=False,
        allow_fragments=False,
        allow_hostname_wildcard=False,
    ):
        """
        :param schemes: List of allowed schemes. E.g.: ["https"]
        :param name: Name of the validated URI. It is required for validation message. E.g.: "Origin"
        :param allow_path: If URI can contain path part
        :param allow_query: If URI can contain query part
        :param allow_fragments: If URI can contain fragments part
        """
        super().__init__(schemes=schemes)
        self.name = name
        self.allow_path = allow_path
        self.allow_query = allow_query
        self.allow_fragments = allow_fragments
        self.allow_hostname_wildcard = allow_hostname_wildcard

    def __call__(self, value):
        value = force_str(value)
        try:
            scheme, netloc, path, query, fragment = urlsplit(value)
        except ValueError as e:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": e},
            )

        # send better validation errors
        if scheme not in self.schemes:
            raise ValidationError(
                "%(name)s URI Validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": "invalid_scheme"},
            )

        # As with the fragment below, urlsplit() reports query == "" both for a URI
        # with no query and for one ending in a bare "?", so the raw string is what
        # distinguishes them.  Only a "?" ahead of any "#" opens a query component;
        # one inside a fragment belongs to the fragment.
        if "?" in value.partition("#")[0] and not self.allow_query:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": "query string not allowed"},
            )
        # Test the raw string rather than the parsed fragment: urlsplit() reports
        # fragment == "" both for a URI with no fragment and for one ending in a
        # bare "#", but the latter carries an (empty) fragment component that
        # RFC 6749 section 3.1.2 forbids just the same.  Catching it here means a
        # misconfiguration is reported at save time, rather than being stored and
        # then never matching -- redirect_to_uri_allowed() denies any "#".
        if "#" in value and not self.allow_fragments:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": "fragment not allowed"},
            )
        if path and not self.allow_path:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": "path not allowed"},
            )

        # A private-use URI scheme redirect (RFC 8252 §7.1) has no authority, so
        # urlsplit() reports an empty netloc and the "{scheme}://{netloc}{path}"
        # reassembly below would rebuild "com.example.app:/oauth2redirect" as
        # "com.example.app:///oauth2redirect".  URIValidator cannot match that:
        # every alternative in host_re consumes at least one character and the
        # next one is "/".  Validate the authority-less form here instead — the
        # scheme is already checked above and there is no host to validate.
        if not netloc:
            if scheme in self.schemes_requiring_authority:
                raise ValidationError(
                    "%(name)s URI validation error. %(cause)s: %(value)s",
                    params={"name": self.name, "value": value, "cause": "missing host"},
                )
            if not self.authorityless_regex.match(value):
                raise ValidationError(
                    "%(name)s URI validation error. %(cause)s: %(value)s",
                    params={"name": self.name, "value": value, "cause": "invalid URI"},
                )
            return

        if self.allow_hostname_wildcard and "*" in netloc:
            domain_parts = netloc.split(".")
            if netloc.count("*") > 1:
                raise ValidationError(
                    "%(name)s URI validation error. %(cause)s: %(value)s",
                    params={
                        "name": self.name,
                        "value": value,
                        "cause": "only one wildcard is allowed in the hostname",
                    },
                )
            if not netloc.startswith("*"):
                raise ValidationError(
                    "%(name)s URI validation error. %(cause)s: %(value)s",
                    params={
                        "name": self.name,
                        "value": value,
                        "cause": "wildcards must be at the beginning of the hostname",
                    },
                )
            if len(domain_parts) < 3:
                raise ValidationError(
                    "%(name)s URI validation error. %(cause)s: %(value)s",
                    params={
                        "name": self.name,
                        "value": value,
                        "cause": "wildcards cannot be in the top level or second level domain",
                    },
                )

            # strip the wildcard from the netloc, we'll reassamble the value later to pass to URI Validator
            if netloc.startswith("*."):
                netloc = netloc[2:]
            else:
                netloc = netloc[1:]

            # Domains cannot start with a hyphen, but can have them in the middle, so strip up to two
            # hyphens after the wildcard. This supports Netlify deploy previews
            # (e.g. *--sitename.netlify.app) while leaving longer runs for URIValidator to reject.
            if netloc.startswith("--"):
                netloc = netloc[2:]
            elif netloc.startswith("-"):
                netloc = netloc[1:]

        # we stripped the wildcard from the netloc and path if they were allowed and present since they would
        # fail validation we'll reassamble the URI to pass to the URIValidator
        reassambled_uri = f"{scheme}://{netloc}{path}"
        if query:
            reassambled_uri += f"?{query}"
        if fragment:
            reassambled_uri += f"#{fragment}"

        try:
            super().__call__(reassambled_uri)
        except ValidationError as e:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": e},
            )


def default_redirect_uri_validator(application: "AbstractApplication") -> AllowedURIValidator:
    """Build the validator applied to each entry in ``Application.redirect_uris``.

    This is the default for the ``REDIRECT_URI_VALIDATOR`` setting, which names a
    *factory*: a callable taking the application and returning a callable that takes a
    single URI string and raises :class:`~django.core.exceptions.ValidationError` when it
    is not acceptable. ``AbstractApplication.clean()`` calls the factory once per
    validation pass, so a policy backed by the database queries once per save rather than
    once per URI. The application may be unsaved (``pk is None``) on the registration
    paths -- Dynamic Client Registration, CIMD and the admin add form -- so a custom
    factory must not assume reverse relations exist.

    A class is a callable too, so a custom validator can subclass
    :class:`AllowedURIValidator` and take the application in ``__init__``, keeping all of
    the RFC 3986 / RFC 8252 parsing above.
    """
    # Imported here rather than at module scope: this module is referenced from migration
    # 0001 and must stay importable before Django settings are configured, and settings.py
    # holds direct references to some defaults (e.g. OAUTH_DEVICE_USER_CODE_GENERATOR), so
    # a module-level import would risk a cycle the moment a default here became one.
    from oauth2_provider.settings import oauth2_settings

    # urlsplit() lowercases the scheme, so the allowed schemes have to be lowercased for
    # AllowedURIValidator's membership test to match. A swapped application model's
    # get_allowed_schemes() may legitimately return e.g. "HTTPS".
    schemes = set(s.lower() for s in application.get_allowed_schemes())
    return AllowedURIValidator(
        schemes,
        name="redirect uri",
        allow_path=True,
        allow_query=True,
        allow_hostname_wildcard=oauth2_settings.ALLOW_URI_WILDCARDS,
    )


def default_allowed_origin_validator(application: "AbstractApplication") -> AllowedURIValidator:
    """Build the validator applied to each entry in ``Application.allowed_origins``.

    This is the default for the ``ALLOWED_ORIGIN_VALIDATOR`` setting. It follows the same
    factory contract as :func:`default_redirect_uri_validator`.
    """
    from oauth2_provider.settings import oauth2_settings

    # The gate is ALLOWED_SCHEMES, whose default is https-only because oauthlib permits only
    # https for CORS; adding "http" is supported for local development, and needs
    # OAUTHLIB_INSECURE_TRANSPORT set as well.
    #
    # Unlike the redirect schemes above, it is passed through exactly as configured. Origins
    # are compared against it verbatim at request time by is_origin_allowed(), so lowercasing
    # here would let clean() accept an origin the request-time check then rejects.
    return AllowedURIValidator(
        oauth2_settings.ALLOWED_SCHEMES,
        "allowed origin",
        allow_hostname_wildcard=oauth2_settings.ALLOW_URI_WILDCARDS,
    )
