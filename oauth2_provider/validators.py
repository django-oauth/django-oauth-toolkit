import re
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.utils.encoding import force_str


class URIValidator(URLValidator):
    scheme_re = r"^(?:[a-z][a-z0-9\.\-\+]*)://"

    dotless_domain_re = r"(?!-)[A-Z\d-]{1,63}(?<!-)"
    host_re = "|".join(
        (r"(?:" + URLValidator.host_re, URLValidator.ipv4_re, URLValidator.ipv6_re, dotless_domain_re + ")")
    )
    port_re = r"(?::\d{2,5})?"
    path_re = r"(?:[/?#][^\s]*)?"
    regex = re.compile(scheme_re + host_re + port_re + path_re, re.IGNORECASE)


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

        if query and not self.allow_query:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": "query string not allowed"},
            )
        if fragment and not self.allow_fragments:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": "fragment not allowed"},
            )
        if path and not self.allow_path:
            raise ValidationError(
                "%(name)s URI validation error. %(cause)s: %(value)s",
                params={"name": self.name, "value": value, "cause": "path not allowed"},
            )

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

            # domains cannot start with a hyphen, but can have them in the middle, so we strip hyphens
            # after the wildcard so the final domain is valid and will succeed in URIVAlidator
            if netloc.startswith("-"):
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
