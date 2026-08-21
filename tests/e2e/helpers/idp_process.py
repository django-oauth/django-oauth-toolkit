"""
Launch the real ``tests/app/idp`` Django project as a live server for black-box
end-to-end testing.

This deliberately runs the IdP exactly as it is deployed (``manage.py`` +
``runserver``) rather than importing its settings in-process, so the compliance
suite talks to it purely over HTTP/HTML the way a real client would. The extra
scopes, relaxed/required PKCE, and extra client applications the suite needs are
supplied through the environment variables the IdP already reads
(``OAUTH2_PROVIDER_*``) plus the ``e2e_seed.json`` fixture — no IdP behaviour is
special-cased for tests.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

from .local_http import poll


REPO_ROOT = Path(__file__).resolve().parents[3]
IDP_DIR = REPO_ROOT / "tests" / "app" / "idp"

DISCOVERY_PATH = "/o/.well-known/openid-configuration"


def _encode_env_dict(mapping):
    """Encode a dict the way django-environ expects (``k=v,k=v``)."""
    return ",".join(f"{k}={v}" for k, v in mapping.items())


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class IdpServer:
    """Manage the lifecycle of a live IdP instance.

    Parameters mirror the knobs the compliance suite needs to flex:

    * ``scopes`` / ``default_scopes`` — the ``SCOPES`` / ``DEFAULT_SCOPES`` the
      IdP is launched with.
    * ``pkce_required`` / ``pkce_required_client_ids`` — global PKCE toggle and
      the set of clients PKCE is enforced for.
    * ``cimd_enabled`` / ``cimd_metadata_fetcher`` — turn on Client ID Metadata
      Document support and (optionally) swap the metadata fetcher import string
      (the CIMD package uses ``idp.cimd.LoopbackMetadataFetcher`` so the IdP
      can fetch documents from a local test server).
    * ``ssl_certfile`` / ``ssl_keyfile`` — serve over TLS. ``runserver`` has no
      TLS support, so the same project is served through uvicorn against
      ``idp.asgi:application`` instead. Only the cross-site browser layer needs
      this; every other caller keeps ``runserver``.
    * ``session_cookie_samesite`` / ``secure_cookies`` / ``csrf_trusted_origins``
      — cookie posture, needed by the cross-site layer (``SameSite=None`` plus
      ``Secure``, without which the OP session cookie can never reach a
      third-party iframe).
    """

    def __init__(
        self,
        host="127.0.0.1",
        port=None,
        scopes=None,
        default_scopes=None,
        pkce_required=False,
        pkce_required_client_ids=None,
        cimd_enabled=False,
        cimd_metadata_fetcher=None,
        fixtures=("fixtures/seed.json", "fixtures/e2e_seed.json"),
        allowed_hosts=None,
        bind_host=None,
        ssl_certfile=None,
        ssl_keyfile=None,
        session_cookie_samesite=None,
        secure_cookies=False,
        csrf_trusted_origins=None,
    ):
        self.host = host
        # ``host`` is the name clients address the server by; ``bind_host`` is
        # the interface it listens on. They differ for the cross-site layer,
        # where idp.test is an /etc/hosts alias for the loopback interface.
        self.bind_host = bind_host or host
        self.port = port or find_free_port()
        # The browser RP addresses the IdP as both localhost and 127.0.0.1
        # (the SPA uses localhost for OIDC and 127.0.0.1 for the device page),
        # so callers can widen ALLOWED_HOSTS beyond the bind host.
        self.allowed_hosts = allowed_hosts or [host]
        self.scopes = scopes
        self.default_scopes = default_scopes or []
        self.pkce_required = pkce_required
        self.pkce_required_client_ids = pkce_required_client_ids or []
        self.cimd_enabled = cimd_enabled
        self.cimd_metadata_fetcher = cimd_metadata_fetcher
        self.fixtures = fixtures
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.session_cookie_samesite = session_cookie_samesite
        self.secure_cookies = secure_cookies
        self.csrf_trusted_origins = csrf_trusted_origins or []
        self._proc = None
        self._tmpdir = None
        self._log = None

    @property
    def scheme(self):
        return "https" if self.ssl_certfile else "http"

    @property
    def base_url(self):
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def issuer(self):
        return f"{self.base_url}/o"

    def url(self, path):
        return f"{self.base_url}{path}"

    def _env(self):
        env = os.environ.copy()
        env["DJANGO_SETTINGS_MODULE"] = "idp.settings"
        env["DATABASE_URL"] = f"sqlite:///{self._tmpdir}/db.sqlite3"
        env["ALLOWED_HOSTS"] = ",".join(self.allowed_hosts)
        # The demo settings hardcode the `runserver` default; this instance binds an
        # arbitrary host/port, and an issuer that does not match it fails OIDC validation.
        env["OAUTH2_PROVIDER_OIDC_ISS_ENDPOINT"] = self.issuer
        if self.scopes:
            env["OAUTH2_PROVIDER_SCOPES"] = _encode_env_dict(self.scopes)
        if self.default_scopes:
            env["OAUTH2_PROVIDER_DEFAULT_SCOPES"] = ",".join(self.default_scopes)
        env["OAUTH2_PROVIDER_PKCE_REQUIRED"] = "True" if self.pkce_required else "False"
        if self.pkce_required_client_ids:
            env["OAUTH2_PROVIDER_PKCE_REQUIRED_CLIENT_IDS"] = ",".join(self.pkce_required_client_ids)
        if self.session_cookie_samesite:
            env["SESSION_COOKIE_SAMESITE"] = self.session_cookie_samesite
        if self.secure_cookies:
            env["SESSION_COOKIE_SECURE"] = "True"
            env["CSRF_COOKIE_SECURE"] = "True"
        if self.csrf_trusted_origins:
            env["CSRF_TRUSTED_ORIGINS"] = ",".join(self.csrf_trusted_origins)
        env["OAUTH2_PROVIDER_CIMD_ENABLED"] = "True" if self.cimd_enabled else "False"
        if self.cimd_metadata_fetcher:
            env["OAUTH2_PROVIDER_CIMD_METADATA_FETCHER"] = self.cimd_metadata_fetcher
        return env

    def _manage(self, *args, env):
        # Capture output so a migrate/loaddata failure surfaces its cause instead
        # of an opaque non-zero exit.
        result = subprocess.run(
            [sys.executable, "manage.py", *args],
            cwd=IDP_DIR,
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"manage.py {' '.join(args)} failed (exit {result.returncode}):\n"
                f"{result.stdout}\n{result.stderr}"
            )

    def start(self, timeout=30):
        self._tmpdir = tempfile.mkdtemp(prefix="dot-e2e-idp-")
        try:
            env = self._env()
            self._manage("migrate", "--no-input", env=env)
            self._manage("loaddata", *self.fixtures, env=env)

            self._log = open(os.path.join(self._tmpdir, "server.log"), "w+")
            self._proc = subprocess.Popen(
                self._server_command(),
                cwd=IDP_DIR,
                env=env,
                stdout=self._log,
                stderr=subprocess.STDOUT,
            )
            self._wait_until_ready(timeout)
        except BaseException:
            # Don't leak the runserver process / log / temp dir on a failed start.
            self.stop()
            raise
        return self

    def _server_command(self):
        """The command that serves the project, with or without TLS."""
        if not self.ssl_certfile:
            return [
                sys.executable,
                "manage.py",
                "runserver",
                f"{self.bind_host}:{self.port}",
                "--noreload",
            ]
        # runserver cannot terminate TLS, so serve the same project through
        # uvicorn. uvicorn terminates TLS itself and reports scheme=https in the
        # ASGI scope, so request.is_secure() is True and no SECURE_PROXY_SSL_HEADER
        # is involved -- there is no proxy in front of it.
        return [
            sys.executable,
            "-m",
            "uvicorn",
            "idp.asgi:application",
            "--host",
            self.bind_host,
            "--port",
            str(self.port),
            "--ssl-certfile",
            str(self.ssl_certfile),
            "--ssl-keyfile",
            str(self.ssl_keyfile),
        ]

    def _wait_until_ready(self, timeout):
        deadline = time.monotonic() + timeout
        url = self.url(DISCOVERY_PATH)
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"IdP process exited early:\n{self.read_log()}")
            try:
                if poll(url).status_code == 200:
                    return
            except requests.RequestException:
                # Connection refused / timeouts are expected while the server is
                # still starting up; keep polling until the deadline.
                pass
            time.sleep(0.2)
        raise RuntimeError(f"IdP did not become ready within {timeout}s:\n{self.read_log()}")

    def read_log(self):
        if not self._log:
            return ""
        self._log.flush()
        self._log.seek(0)
        return self._log.read()

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=10)
        if self._log:
            self._log.close()
        if self._tmpdir and os.path.isdir(self._tmpdir):
            import shutil

            shutil.rmtree(self._tmpdir, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
