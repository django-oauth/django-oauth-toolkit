"""
Authorization-request ``response_type`` canonicalization.

A multi-valued ``response_type`` is a space-delimited list whose order does not matter
(RFC 6749 §3.1.1; OAuth 2.0 Multiple Response Type Encoding Practices §4), so
``id_token code`` means the same as ``code id_token``. oauthlib routes an authorization
request by exact-string lookup of ``response_type`` in its endpoint registry, which holds
one ordering of each value. These helpers map a value to the ordering the server
registered, so every ordering is served alike.
"""

from collections.abc import Collection
from urllib.parse import quote, unquote_plus


def canonical_response_type(response_type: str | None, registered: Collection[str]) -> str | None:
    """
    Return the ordering of ``response_type`` that appears in ``registered``.

    ``response_type`` is returned unchanged when it is already registered, or when no
    registered value has the same set of response-type names. A value with an empty
    name (a leading, trailing or repeated space) or a name given twice is not a valid
    ``response-type`` (RFC 6749 Appendix A.3) and is returned unchanged too, so it is
    rejected exactly as before.
    """
    if response_type is None or response_type in registered:
        return response_type
    names = response_type.split(" ")
    if "" in names or len(set(names)) != len(names):
        return response_type
    wanted = frozenset(names)
    for candidate in registered:
        if frozenset(candidate.split(" ")) == wanted:
            return candidate
    return response_type


def canonicalize_response_type_parameter(encoded: str, registered: Collection[str]) -> str:
    """
    Rewrite each ``response_type`` in an ``application/x-www-form-urlencoded`` string.

    Each value is replaced by :func:`canonical_response_type`. Every other parameter,
    and every value that needs no change, is kept byte for byte, so the string still
    carries the same parameters, duplicates included, in the same order.
    """
    pairs = encoded.split("&")
    for index, pair in enumerate(pairs):
        name, separator, value = pair.partition("=")
        if not separator or unquote_plus(name) != "response_type":
            continue
        response_type = unquote_plus(value)
        canonical = canonical_response_type(response_type, registered)
        if canonical != response_type:
            pairs[index] = f"{name}={quote(canonical, safe='')}"
    return "&".join(pairs)
