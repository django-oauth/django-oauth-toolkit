"""
A readiness-poll GET for the servers this suite launches.

The IdP and RP are always local processes, but the cross-site layer addresses
them by hostnames that do not look local (``idp.test`` / ``rp.test``) and serves
them with a throwaway self-signed certificate. Both facts have to be spelled out
per request, so they live here rather than being repeated at each call site.
"""

import warnings

import requests
import urllib3


# Never route a poll for a local process through an ambient HTTP(S)_PROXY.
_NO_PROXY = {"http": None, "https": None}


def poll(url, timeout=2):
    """GET ``url`` as a liveness check: no proxy, no certificate verification."""
    with warnings.catch_warnings():
        # Verifying the throwaway certificate is not the point of a liveness
        # check, and pytest re-enables this warning per test.
        warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
        return requests.get(url, timeout=timeout, verify=False, proxies=_NO_PROXY)
