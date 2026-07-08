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
    """

    def __init__(
        self,
        host="127.0.0.1",
        port=None,
        scopes=None,
        default_scopes=None,
        pkce_required=False,
        pkce_required_client_ids=None,
        fixtures=("fixtures/seed.json", "fixtures/e2e_seed.json"),
        allowed_hosts=None,
    ):
        self.host = host
        self.port = port or find_free_port()
        # The browser RP addresses the IdP as both localhost and 127.0.0.1
        # (the SPA uses localhost for OIDC and 127.0.0.1 for the device page),
        # so callers can widen ALLOWED_HOSTS beyond the bind host.
        self.allowed_hosts = allowed_hosts or [host]
        self.scopes = scopes
        self.default_scopes = default_scopes or []
        self.pkce_required = pkce_required
        self.pkce_required_client_ids = pkce_required_client_ids or []
        self.fixtures = fixtures
        self._proc = None
        self._tmpdir = None
        self._log = None

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

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
        if self.scopes:
            env["OAUTH2_PROVIDER_SCOPES"] = _encode_env_dict(self.scopes)
        if self.default_scopes:
            env["OAUTH2_PROVIDER_DEFAULT_SCOPES"] = ",".join(self.default_scopes)
        env["OAUTH2_PROVIDER_PKCE_REQUIRED"] = "True" if self.pkce_required else "False"
        if self.pkce_required_client_ids:
            env["OAUTH2_PROVIDER_PKCE_REQUIRED_CLIENT_IDS"] = ",".join(self.pkce_required_client_ids)
        return env

    def _manage(self, *args, env):
        subprocess.run(
            [sys.executable, "manage.py", *args],
            cwd=IDP_DIR,
            env=env,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

    def start(self, timeout=30):
        self._tmpdir = tempfile.mkdtemp(prefix="dot-e2e-idp-")
        env = self._env()
        self._manage("migrate", "--no-input", env=env)
        self._manage("loaddata", *self.fixtures, env=env)

        self._log = open(os.path.join(self._tmpdir, "server.log"), "w+")
        self._proc = subprocess.Popen(
            [sys.executable, "manage.py", "runserver", f"{self.host}:{self.port}", "--noreload"],
            cwd=IDP_DIR,
            env=env,
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        self._wait_until_ready(timeout)
        return self

    def _wait_until_ready(self, timeout):
        deadline = time.monotonic() + timeout
        url = self.url(DISCOVERY_PATH)
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"IdP process exited early:\n{self.read_log()}")
            try:
                if requests.get(url, timeout=2).status_code == 200:
                    return
            except requests.RequestException:
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
