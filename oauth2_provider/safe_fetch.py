"""
SSRF-hardened outbound HTTPS fetching.

Shared by features that fetch documents from URLs controlled by OAuth clients:
Client ID Metadata Documents (``cimd.py``) and RFC 7523 ``jwks_uri`` key sets
(``client_assertions.py``). Such fetches happen inside request handling, so
the helpers here are hardened against SSRF (https only, resolve and validate
the target IP once then connect to that same IP, no redirects, tight
timeouts, response size caps).

Callers pass their own exception class so failures surface as the feature's
native error type (e.g. ``CIMDError``); everything raised here is an instance
of that class (or of :class:`SafeFetchError` by default).
"""

import ipaddress
import json
import socket
import ssl
import time
from urllib.parse import urlsplit

import urllib3


# NAT64 well-known prefix (RFC 6052): 64:ff9b::/96 addresses embed an IPv4 in
# their low 32 bits, so they must be decoded before the public-IP check.
NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")

JSON_ACCEPT = "application/json, application/*+json"


class SafeFetchError(Exception):
    """A document could not be safely fetched.

    The message is safe to log but should never be returned to the client.
    """


def ip_is_public(ip_str):
    """Return True only for a globally routable address.

    ``ipaddress.is_global`` excludes private, loopback, link-local (including
    the 169.254.169.254 cloud-metadata address), CGNAT, multicast, reserved and
    unspecified ranges. But several IPv6 forms embed an IPv4 address that
    ``is_global`` can misjudge — IPv4-mapped ``::ffff:0:0/96`` (only fixed in
    newer CPython patch levels), 6to4, Teredo ``2001::/32``, and the NAT64
    well-known prefix ``64:ff9b::/96`` — so decode the embedded IPv4 and judge
    that instead. Otherwise a crafted AAAA record could smuggle an internal
    IPv4 (e.g. the cloud-metadata address) past the allowlist.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        teredo = ip.teredo
        if teredo is not None:
            # (server, de-obfuscated client) IPv4 pair; both must be public.
            return all(part.is_global for part in teredo)
        embedded = ip.ipv4_mapped or ip.sixtofour
        if embedded is None and ip in NAT64_PREFIX:
            # The low 32 bits of a 64:ff9b::/96 address are the embedded IPv4.
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is not None:
            ip = embedded
    return ip.is_global


def resolve_and_validate(hostname, port, *, exc_class=SafeFetchError):
    """Resolve *hostname* and return its validated IPs, or raise *exc_class*.

    Every resolved address must be public; if any is internal we refuse the
    whole host rather than cherry-pick a good one, so a split public/private
    result can't smuggle a connection to an internal service.
    """
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise exc_class(f"could not resolve host: {exc}") from exc
    ips = []
    for info in infos:
        ip = info[4][0]
        if not ip_is_public(ip):
            raise exc_class(f"host resolves to a non-public address ({ip})")
        ips.append(ip)
    if not ips:
        raise exc_class("host did not resolve to any address")
    return ips


def fetch_https_document(url, *, timeout, read_response, exc_class=SafeFetchError, accept=JSON_ACCEPT):
    """GET *url* with SSRF pinning and hand the urllib3 response to *read_response*.

    The URL must be https with a hostname. Every address the host resolves to
    is validated as public before any connection is made, and each attempt
    connects to a validated IP directly — SNI, certificate verification and the
    Host header all use the real hostname, so a second DNS lookup can't rebind
    the connection to another address. Redirects are never followed.

    *read_response* receives the (unread, streaming) response of the first
    attempt that yields one and its return value is returned; it must enforce
    the caller's own status/size/content checks. Raises *exc_class* when the
    URL is invalid, resolution fails, or every address attempt errors.
    """
    # urlsplit, not urlparse: urlparse splits a legacy ";params" component off
    # the last path segment, which would silently drop it from the fetched
    # target; urlsplit keeps the path verbatim.
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise exc_class("URL must use the https scheme")
    if not parsed.hostname:
        raise exc_class("URL must contain a host")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise exc_class("URL has an invalid port") from exc
    # Presence check, not truthiness: https://@example.com/ has an empty but
    # present userinfo component (and would leak the "@" into the Host header
    # via parsed.netloc).
    if parsed.username is not None or parsed.password is not None:
        raise exc_class("URL must not contain a userinfo component")

    ips = resolve_and_validate(parsed.hostname, port, exc_class=exc_class)

    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    # parsed.netloc is the authority minus userinfo (already rejected), so it
    # carries the port and IPv6 brackets that the Host header needs.
    # The structured-suffix range is advertised because JSON readers accept
    # application/<subtype>+json, and a server honouring Accept strictly could
    # otherwise answer 406.
    headers = {"Host": parsed.netloc, "Accept": accept}
    ssl_context = ssl.create_default_context()

    # One deadline shared across every IP attempt. A hostname can resolve to
    # many public IPs; giving each attempt its own total=timeout would let N
    # addresses hold a worker for N × timeout. Each attempt instead gets only
    # the remaining budget, so the whole fetch stays bounded by *timeout*
    # regardless of address count.
    deadline = time.monotonic() + timeout

    last_exc = None
    for ip in ips:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        # Connect to the validated IP (host=ip); total=remaining bounds this
        # attempt (connect + all reads) to the shared deadline, so a slow-drip
        # body can't hold the worker past it.
        pool = urllib3.HTTPSConnectionPool(
            host=ip,
            port=port,
            timeout=urllib3.Timeout(connect=remaining, read=remaining, total=remaining),
            retries=False,
            maxsize=1,
            ssl_context=ssl_context,
            server_hostname=parsed.hostname,
        )
        try:
            response = pool.urlopen(
                "GET",
                path,
                headers=headers,
                redirect=False,
                preload_content=False,
            )
            try:
                return read_response(response)
            finally:
                response.release_conn()
        except urllib3.exceptions.HTTPError as exc:
            last_exc = exc
        finally:
            pool.close()
    if last_exc is None:
        raise exc_class("could not fetch document: timeout budget exhausted before any connection attempt")
    raise exc_class(f"could not fetch document: {last_exc}")


def media_type_is_json(content_type):
    """True for application/json and RFC 6839 application/<subtype>+json."""
    media_type = (content_type or "").split(";")[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def fetch_https_json(url, *, timeout, max_size, exc_class=SafeFetchError):
    """Fetch *url* (SSRF-pinned) and return its body as a parsed JSON object.

    Enforces HTTP 200, a JSON media type, the *max_size* byte cap and that the
    body is a JSON object. Returns ``(data, response_headers)``.
    """

    def _read(response):
        if response.status != 200:
            raise exc_class(f"document returned HTTP {response.status}")
        if not media_type_is_json(response.headers.get("Content-Type")):
            raise exc_class(f"document is not JSON (Content-Type: {response.headers.get('Content-Type')!r})")
        body = response.read(max_size + 1)
        if len(body) > max_size:
            raise exc_class("document exceeds the maximum allowed size")
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            raise exc_class("document is not valid JSON") from exc
        if not isinstance(data, dict):
            raise exc_class("document must be a JSON object")
        return data, response.headers

    return fetch_https_document(url, timeout=timeout, read_response=_read, exc_class=exc_class)
