"""
A loopback endpoint standing in for a Relying Party's back-channel logout URI.

Back-Channel Logout 1.0 section 2.5 has the OP POST the Logout Token directly to a URI
the RP registered out of band, so the only way to observe the mechanism end to end is to
*be* that endpoint. This takes the same shape the OpenID Foundation conformance suite
does -- the suite registers its own ``backchannel_logout_uri`` and asserts on what
arrives there -- with its hosted receiver replaced by one on the loopback interface, so
the suite can run self-contained and without public ingress.
"""

import http.server
import threading
import time
from urllib.parse import parse_qs


class BackchannelLogoutReceiver:
    """Record the logout requests an OP sends, and answer them per section 2.8."""

    PATH = "/backchannel-logout"

    def __init__(self):
        received = self._received = []
        lock = self._lock = threading.Lock()
        path = self.PATH
        # Section 2.8 gives the RP a 400 to signal a logout it could not perform. A
        # test can switch to it to stand in for a broken relying party, which must not
        # change the outcome of the logout itself.
        self.response_status = 200
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode()
                if self.path != path:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                with lock:
                    received.append(
                        {
                            "content_type": self.headers.get("Content-Type", ""),
                            "body": body,
                            "form": parse_qs(body),
                        }
                    )
                # Section 2.8: a 200 means the logout succeeded, and the response must
                # not be cached where it could interfere with a later logout request.
                self.send_response(owner.response_status)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                # Keep the test output free of per-request access logging.
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def uri(self):
        """The URI to register as the RP's ``backchannel_logout_uri``."""
        return f"http://127.0.0.1:{self.port}{self.PATH}"

    @property
    def received(self):
        with self._lock:
            return list(self._received)

    def wait_for(self, count=1, timeout=10):
        """Block until *count* requests have arrived, and return them.

        The OP answers the logout request before -- or while -- it delivers the logout
        tokens, and may deliver them from a worker thread, so nothing guarantees a
        request has landed by the time the HTTP response reaches the client.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self.received
            if len(current) >= count:
                return current
            time.sleep(0.05)
        raise AssertionError(
            f"expected {count} back-channel logout request(s) at {self.uri}, "
            f"got {len(self.received)} within {timeout}s"
        )

    def logout_tokens(self):
        """The ``logout_token`` parameter of every request received, in order."""
        return [r["form"]["logout_token"][0] for r in self.received if "logout_token" in r["form"]]

    def reset(self):
        with self._lock:
            self._received.clear()
        self.response_status = 200

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
