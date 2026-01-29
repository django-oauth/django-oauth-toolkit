import base64
from unittest import mock


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
