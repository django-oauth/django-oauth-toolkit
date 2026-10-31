"""
The demo RP's back-channel logout endpoint, served the way it is in production.

``npm run dev`` skips SvelteKit's origin checks, which a production build applies to every
form POST -- including the OP's server-to-server logout POST, which carries no Origin
header. ``tests/app/rp/server.js`` is the production entry point that admits that one
request. These tests build the RP, run it through ``server.js`` and have the demo IdP
deliver a real logout token to it.

They need Node and npm, and follow the browser layer's rules: skipped where those are
missing, a failure when ``E2E_REQUIRE_BROWSER`` is set.
"""

import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest
import requests

from tests.e2e import constants as c
from tests.e2e.helpers.browser import skip_or_fail
from tests.e2e.helpers.oauth_client import token_data


RP_DIR = Path(__file__).resolve().parents[2] / "app" / "rp"
# Its own SvelteKit output directory, so building cannot disturb a dev server another
# e2e package may have running out of the same project.
OUT_DIR = ".svelte-kit-production-e2e"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ProductionRp:
    """``node server.js`` on a free loopback port, with its output captured."""

    def __init__(self, port, env):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self._log = open(RP_DIR / f".rp-production-{port}.log", "w+")
        self.proc = subprocess.Popen(
            ["node", "server.js"],
            cwd=RP_DIR,
            env={**os.environ, "HOST": "127.0.0.1", "PORT": str(port), **env},
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self._fail_to_start("server.js exited early")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        self._fail_to_start("server.js did not start")

    def _fail_to_start(self, reason):
        # The caller never gets an instance to stop, so clean up before raising.
        log = self.log()
        self.stop()
        raise RuntimeError(f"{reason}:\n{log}")

    def log(self):
        self._log.flush()
        self._log.seek(0)
        return self._log.read()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
        self._log.close()
        os.unlink(self._log.name)


@pytest.fixture(scope="module")
def production_build():
    if not shutil.which("node") or not shutil.which("npm"):
        skip_or_fail("Node and npm are needed to build the demo RP")
    if not (RP_DIR / "node_modules").is_dir():
        subprocess.run(["npm", "install"], cwd=RP_DIR, check=True)
    result = subprocess.run(
        ["npm", "run", "build"],
        cwd=RP_DIR,
        env={**os.environ, "RP_OUT_DIR": OUT_DIR},
        capture_output=True,
        text=True,
    )
    if result.returncode:
        pytest.fail(f"npm run build failed:\n{result.stdout}\n{result.stderr}")


@pytest.fixture
def start_rp(production_build):
    started = []

    def start(port=None, **env):
        rp = ProductionRp(port or _free_port(), env)
        started.append(rp)
        return rp

    yield start
    for rp in started:
        rp.stop()


def _form_post(url, **headers):
    return requests.post(
        url,
        data={"logout_token": "not-a-token"},
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
        timeout=10,
    )


def test_production_rp_processes_a_logout_token_from_the_op(backchannel_idp, backchannel_oauth, start_rp):
    port = _free_port()
    registered = requests.post(
        backchannel_oauth.url("/o/register/"),
        json={
            "client_name": "E2E production demo RP",
            "redirect_uris": [c.REDIRECT_URI],
            "post_logout_redirect_uris": [c.POST_LOGOUT_REDIRECT_URI],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "client_secret_basic",
            "backchannel_logout_uri": f"http://127.0.0.1:{port}/api/backchannel-logout",
        },
        timeout=10,
    ).json()
    rp = start_rp(port, PUBLIC_RP_ISSUER=backchannel_idp.issuer, PUBLIC_RP_CLIENT_ID=registered["client_id"])

    session = backchannel_oauth.login(c.E2E_USERNAME, c.E2E_PASSWORD)
    code = backchannel_oauth.authorize(
        session,
        client_id=registered["client_id"],
        response_type="code",
        redirect_uri=c.REDIRECT_URI,
        scope="openid",
        state="s",
    ).query_params["code"]
    id_token = token_data(
        backchannel_oauth.exchange_code(
            client_id=registered["client_id"],
            code=code,
            redirect_uri=c.REDIRECT_URI,
            client_secret=registered["client_secret"],
        )
    )["id_token"]
    response = backchannel_oauth.rp_logout(
        session, id_token_hint=id_token, post_logout_redirect_uri=c.POST_LOGOUT_REDIRECT_URI, state="s"
    )
    assert response.status_code == 302

    # The OP delivers before it answers, so the RP has already handled the token.
    assert "Processed backchannel logout" in rp.log(), rp.log()


def test_production_rp_keeps_origin_checks_on_every_other_route(start_rp):
    # The exemption covers the logout endpoint's server-to-server POST, nothing else.
    rp = start_rp()
    assert _form_post(f"{rp.url}/par").status_code == 403
    assert _form_post(f"{rp.url}/par", Origin="https://evil.example").status_code == 403
    assert _form_post(f"{rp.url}/private-key-jwt").status_code == 403
    # A browser posting from another site to the logout endpoint is still refused.
    assert _form_post(f"{rp.url}/api/backchannel-logout", Origin="https://evil.example").status_code == 403


def test_production_rp_admits_the_op_behind_a_proxy(start_rp):
    # Behind a load balancer reporting the default port, or a host in upper case, the origin
    # SvelteKit compares against is the normalised one; the OP's POST must still reach the
    # endpoint, whose own validation then answers.
    rp = start_rp(
        PROTOCOL_HEADER="x-forwarded-proto", HOST_HEADER="x-forwarded-host", PORT_HEADER="x-forwarded-port"
    )
    response = _form_post(
        f"{rp.url}/api/backchannel-logout",
        **{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "RP.Example", "X-Forwarded-Port": "443"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_production_rp_answers_a_non_form_request_with_400(start_rp):
    # Section 2.8: an invalid logout request gets 400 Bad Request.
    rp = start_rp()
    response = requests.post(f"{rp.url}/api/backchannel-logout", json={"logout_token": "x"}, timeout=10)
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_production_rp_shuts_down_on_sigterm(start_rp):
    # As adapter-node's own entry point does, so that `docker stop` need not kill it.
    rp = start_rp()
    rp.proc.send_signal(signal.SIGTERM)
    assert rp.proc.wait(10) == 0
