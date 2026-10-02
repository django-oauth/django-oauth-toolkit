import base64
from unittest import mock
from urllib.parse import urlencode


#: The media type RFC 6749 section 3.2 (and the specs that reuse it) require for the
#: request bodies of the token, revocation, introspection, device authorization and
#: pushed authorization request endpoints.
FORM_URLENCODED = "application/x-www-form-urlencoded"


def get_basic_auth_header(user, password):
    """
    Return a dict containing the correct headers to set to make HTTP Basic
    Auth request
    """
    user_pass = "{0}:{1}".format(user, password)
    auth_string = base64.b64encode(user_pass.encode("utf-8"))
    auth_headers = {
        "HTTP_AUTHORIZATION": "Basic " + auth_string.decode("utf-8"),
    }

    return auth_headers


def post_form(client, path, data=None, **extra):
    """
    POST ``data`` to ``path`` as an ``application/x-www-form-urlencoded`` body.

    Use this for requests to the token, revocation, introspection, device authorization
    and pushed authorization request endpoints, whose bodies the specifications define
    as form-encoded. Django's test client encodes a dict as ``multipart/form-data`` by
    default, which is rejected with HTTP 415 once ``REQUIRE_FORM_ENCODED_REQUEST_BODY``
    is enabled and warns until then; the pytest configuration turns that warning into
    an error, so a test that posts a dict to these endpoints fails. Sequence values are
    sent as repeated parameters, as the multipart encoding did.
    """
    # The test client only sets the Content-Type header for a non-empty body, so set it
    # directly to keep an empty form body form-encoded too.
    extra.setdefault("CONTENT_TYPE", FORM_URLENCODED)
    return client.post(path, data=urlencode(data or {}, doseq=True), content_type=FORM_URLENCODED, **extra)


def spy_on(meth):
    """
    Util function to add a spy onto a method of a class.
    """
    spy = mock.MagicMock()

    def wrapper(self, *args, **kwargs):
        spy(self, *args, **kwargs)
        return_value = meth(self, *args, **kwargs)
        spy.returned = return_value
        return return_value

    wrapper.spy = spy
    return wrapper
