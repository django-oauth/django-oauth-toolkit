"""
Authorization-response encoding (OAuth 2.0 Multiple Response Type Encoding Practices).

The authorization endpoint returns its parameters either in the query or in the
fragment of the redirect URI. These helpers choose between the two the same way for
successful and error responses, as OpenID Connect Core 3.2.2.6 and 3.3.2.6 require.
"""


def response_type_requires_fragment(response_type: str | None) -> bool:
    """
    Return whether ``response_type`` must be returned in the fragment.

    Any response type that includes ``token`` or ``id_token`` returns credentials in
    the front channel. Its default response mode is ``fragment``, and the query
    encoding must not be used for it (OAuth 2.0 Multiple Response Type Encoding
    Practices §§2.1, 3 and 5).
    """
    return bool(set((response_type or "").split()) & {"token", "id_token"})


#: The response modes this authorization server supports.
SUPPORTED_RESPONSE_MODES = ("query", "fragment")


def response_mode_permitted(response_type: str | None, response_mode: str) -> bool:
    """
    Return whether an explicitly requested ``response_mode`` can be honoured.

    Only the modes in :data:`SUPPORTED_RESPONSE_MODES` are supported, and ``query``
    is not permitted for a response type that must use the fragment.
    """
    if response_mode not in SUPPORTED_RESPONSE_MODES:
        return False
    return not (response_mode == "query" and response_type_requires_fragment(response_type))


def authorization_response_uses_fragment(response_type: str | None, response_mode: str | None) -> bool:
    """
    Return whether an authorization response is encoded in the redirect URI fragment.

    Response types that must use the fragment always do, even if the request asked
    for ``response_mode=query``: such a request is rejected, and its error must not
    be returned in the query. Other response types use the fragment only if it was
    requested explicitly.
    """
    return response_type_requires_fragment(response_type) or response_mode == "fragment"


def add_params_to_authorization_redirect(
    redirect_uri: str, params: str, response_type: str | None, response_mode: str | None
) -> str:
    """
    Append url-encoded authorization-response ``params`` to ``redirect_uri``.

    The parameters go in the fragment or the query according to
    :func:`authorization_response_uses_fragment`. A registered redirect URI has no
    fragment (RFC 6749 §3.1.2), so the fragment is the parameters alone.
    """
    if authorization_response_uses_fragment(response_type, response_mode):
        return f"{redirect_uri}#{params}"
    separator = "&" if "?" in redirect_uri else "?"
    return redirect_uri + separator + params
