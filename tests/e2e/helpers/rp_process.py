"""
Launch the real SvelteKit relying party (``tests/app/rp``) for the browser
layer of the compliance suite.

The RP defaults (in ``src/routes/+page.svelte``) to an IdP at
``http://localhost:8000`` using the seed OIDC client, and to
``http://localhost:5173`` as its redirect URI — so the browser tests pin the IdP
to port 8000 and serve the RP on 5173. Those defaults are overridable through
``PUBLIC_RP_*`` environment variables, which is how the cross-site layer points
the same app at ``https://idp.test:8443`` / ``https://rp.test:5443``.
"""

import os
import signal
import subprocess
import time
from pathlib import Path

import requests

from .local_http import poll


REPO_ROOT = Path(__file__).resolve().parents[3]
RP_DIR = REPO_ROOT / "tests" / "app" / "rp"


def chromium_executable():
    """Resolve a usable Chromium for Playwright.

    Prefers ``E2E_CHROMIUM_PATH``; then a pre-installed build under
    ``PLAYWRIGHT_BROWSERS_PATH`` (as shipped in CI images where the pip
    Playwright's own build may not match); otherwise ``None`` so Playwright uses
    its bundled browser.
    """
    return _playwright_executable("E2E_CHROMIUM_PATH", "chromium-*/chrome-linux/chrome", "chromium-")


def firefox_executable():
    """Resolve a usable Firefox for Playwright, the same way as Chromium.

    Prefers ``E2E_FIREFOX_PATH``; then a pre-installed build under
    ``PLAYWRIGHT_BROWSERS_PATH``; otherwise ``None`` so Playwright uses its
    bundled browser.
    """
    return _playwright_executable("E2E_FIREFOX_PATH", "firefox-*/firefox/firefox", "firefox-")


def _playwright_executable(env_var, glob_pattern, directory_prefix):
    explicit = os.environ.get(env_var)
    if explicit and os.path.exists(explicit):
        return explicit
    browsers_root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if browsers_root:
        matches = list(Path(browsers_root).glob(glob_pattern))
        if matches:
            # Pick the highest build revision by numeric value, not lexicographic
            # order (so chromium-1234 beats chromium-999).
            return str(max(matches, key=lambda path: _revision(path, directory_prefix)))
    return None


def _revision(browser_path, directory_prefix):
    """Extract the numeric build revision from a ``<prefix><rev>/...`` path."""
    for part in browser_path.parts:
        if part.startswith(directory_prefix):
            rev = part[len(directory_prefix) :]
            return int(rev) if rev.isdigit() else -1
    return -1


class RpServer:
    """Manage the lifecycle of the SvelteKit dev server.

    ``host`` is the name the browser addresses the RP by; ``bind_host`` is the
    interface Vite listens on (they differ for the cross-site layer, where
    rp.test is an /etc/hosts alias for loopback). ``env`` is merged over the
    inherited environment, which is how the ``PUBLIC_RP_*`` configuration
    reaches the app. Passing ``tls_cert``/``tls_key`` serves it over HTTPS.

    ``isolate_build`` gives this instance its own SvelteKit output and Vite
    cache directories. Two dev servers running out of the one project directory
    otherwise share ``.svelte-kit/`` and invalidate each other's module graph
    mid-request, which surfaces as unrelated browser tests failing whenever both
    happen to be alive at once.
    """

    def __init__(
        self,
        host="localhost",
        port=5173,
        bind_host=None,
        env=None,
        tls_cert=None,
        tls_key=None,
        isolate_build=False,
    ):
        self.host = host
        self.bind_host = bind_host or host
        self.port = port
        self.extra_env = env or {}
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.isolate_build = isolate_build
        self._proc = None
        self._log = None

    @property
    def scheme(self):
        return "https" if self.tls_cert else "http"

    @property
    def base_url(self):
        return f"{self.scheme}://{self.host}:{self.port}"

    def _ensure_dependencies(self):
        if not (RP_DIR / "node_modules").is_dir():
            subprocess.run(["npm", "install"], cwd=RP_DIR, check=True)

    def start(self, timeout=90):
        self._ensure_dependencies()
        try:
            # Per-port log name so two RP instances can run side by side.
            self._log = open(os.path.join(os.getcwd(), f".rp-server-{self.port}.log"), "w+")
            self._proc = subprocess.Popen(
                [
                    "npm",
                    "run",
                    "dev",
                    "--",
                    "--port",
                    str(self.port),
                    "--strictPort",
                    "--host",
                    self.bind_host,
                ],
                cwd=RP_DIR,
                env=self._env(),
                stdout=self._log,
                stderr=subprocess.STDOUT,
                # `npm run dev` is only a wrapper: vite runs as its child.
                # Terminating npm alone leaves vite alive and holding the port,
                # so give the pair its own process group and signal the group.
                start_new_session=True,
            )
            self._wait_until_ready(timeout)
        except BaseException:
            # Don't leak the Node dev server process / log on a failed start.
            self.stop()
            raise
        return self

    def _env(self):
        """The child environment: the inherited one plus the RP's own config."""
        env = os.environ.copy()
        # Vite refuses requests whose Host header it does not recognise, so a
        # non-localhost hostname has to be allow-listed explicitly.
        env["RP_ALLOWED_HOSTS"] = self.host
        if self.tls_cert:
            env["RP_TLS_CERT"] = str(self.tls_cert)
            env["RP_TLS_KEY"] = str(self.tls_key)
        if self.isolate_build:
            # Relative to the RP project directory; both are gitignored.
            env["RP_OUT_DIR"] = f".svelte-kit-{self.port}"
            env["RP_CACHE_DIR"] = f".vite-{self.port}"
        env.update(self.extra_env)
        return env

    def _wait_until_ready(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"RP process exited early:\n{self.read_log()}")
            try:
                if poll(self.base_url).status_code == 200:
                    return
            except requests.RequestException:
                # Connection errors/timeouts are expected until the dev server is
                # ready; keep polling until the deadline.
                pass
            time.sleep(0.3)
        raise RuntimeError(f"RP did not become ready within {timeout}s:\n{self.read_log()}")

    def read_log(self):
        if not self._log:
            return ""
        self._log.flush()
        self._log.seek(0)
        return self._log.read()

    def stop(self):
        if self._proc and self._proc.poll() is None:
            self._signal_group(signal.SIGTERM)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._signal_group(signal.SIGKILL)
                self._proc.wait(timeout=10)
        if self._log:
            self._log.close()

    def _signal_group(self, sig):
        """Signal the whole npm+vite process group, falling back to the wrapper."""
        try:
            os.killpg(os.getpgid(self._proc.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            # The group is already gone, or the platform would not give us one.
            self._proc.send_signal(sig)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
