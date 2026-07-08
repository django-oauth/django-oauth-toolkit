"""
Launch the real SvelteKit relying party (``tests/app/rp``) for the browser
layer of the compliance suite.

The RP is hard-configured (in ``src/routes/+page.svelte``) to talk to an IdP at
``http://localhost:8000`` using the seed OIDC client, and to use
``http://localhost:5173`` as its redirect URI — so the browser tests pin the IdP
to port 8000 and serve the RP on 5173.
"""

import os
import subprocess
import time
from pathlib import Path

import requests


REPO_ROOT = Path(__file__).resolve().parents[3]
RP_DIR = REPO_ROOT / "tests" / "app" / "rp"


def chromium_executable():
    """Resolve a usable Chromium for Playwright.

    Prefers ``E2E_CHROMIUM_PATH``; then a pre-installed build under
    ``PLAYWRIGHT_BROWSERS_PATH`` (as shipped in CI images where the pip
    Playwright's own build may not match); otherwise ``None`` so Playwright uses
    its bundled browser.
    """
    explicit = os.environ.get("E2E_CHROMIUM_PATH")
    if explicit and os.path.exists(explicit):
        return explicit
    browsers_root = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if browsers_root:
        matches = sorted(Path(browsers_root).glob("chromium-*/chrome-linux/chrome"))
        if matches:
            return str(matches[-1])
    return None


class RpServer:
    def __init__(self, host="localhost", port=5173):
        self.host = host
        self.port = port
        self._proc = None
        self._log = None

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

    def _ensure_dependencies(self):
        if not (RP_DIR / "node_modules").is_dir():
            subprocess.run(["npm", "install"], cwd=RP_DIR, check=True)

    def start(self, timeout=90):
        self._ensure_dependencies()
        self._log = open(os.path.join(os.getcwd(), ".rp-server.log"), "w+")
        self._proc = subprocess.Popen(
            ["npm", "run", "dev", "--", "--port", str(self.port), "--strictPort", "--host", self.host],
            cwd=RP_DIR,
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        self._wait_until_ready(timeout)
        return self

    def _wait_until_ready(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"RP process exited early:\n{self.read_log()}")
            try:
                if requests.get(self.base_url, timeout=2).status_code == 200:
                    return
            except requests.RequestException:
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
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=10)
        if self._log:
            self._log.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
