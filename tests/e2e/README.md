# OAuth 2.0 / OpenID Connect End-to-End Compliance Suite

This suite exercises **every OAuth 2.0 / OpenID Connect flow that
django-oauth-toolkit supports**, end-to-end and black-box, against the real
demo apps in `tests/app/`:

* **`tests/app/idp`** — the toolkit configured as a live OAuth2/OIDC provider.
  It is booted as an actual server process (`runserver`, or uvicorn where the
  cross-site layer needs TLS) rather than imported in-process, so the tests talk
  to it purely over HTTP/HTML the way a real client would.
* **`tests/app/rp`** — the SvelteKit relying party, driven through Chromium (and,
  for the cross-site layer, Firefox) with Playwright for the browser layer.

Tests are **organized by specification** (one package per RFC / OIDC spec) and
every check is tagged with a `@pytest.mark.compliance(spec, section, requirement)`
marker, so the results double as a **compliance matrix** for tracking and
reporting.

## Running

```bash
# Everything (protocol + browser), with JUnit + compliance matrix under reports/
tox -e e2e

# A single specification
tox -e e2e -- -m spec_rfc7636

# Skip deprecated flows (implicit, ROPC) and/or the browser layer
tox -e e2e -- -m "not deprecated and not browser"
```

Or directly with pytest (from a venv with the toolkit + `requests`, `jwcrypto`,
and optionally `playwright`/`pytest-playwright` installed):

```bash
pytest tests/e2e --confcutdir=tests/e2e -o addopts=
```

`--confcutdir=tests/e2e` is required so the black-box suite does not load the
in-process unit suite's `tests/conftest.py` (which configures Django).

The browser tests self-skip when Node or Playwright is unavailable, so the
protocol suite still runs in minimal environments. Set `E2E_REQUIRE_BROWSER=1`
(as the CI job does) to make a missing/broken browser a hard failure instead of
a skip, so the browser RP coverage cannot be silently dropped. A pre-installed
browser can be pointed at with `E2E_CHROMIUM_PATH` / `E2E_FIREFOX_PATH`.

### The cross-site (third-party cookie) layer

`browser_cross_site/` runs a **second** IdP + RP pair, on `idp.test` and
`rp.test`, over HTTPS with a self-signed certificate generated per session. Two
things about that setup are load-bearing rather than incidental:

* **Distinct registrable domains.** On `localhost:8000` / `localhost:5173` ports
  do not count toward "site", so a browser treats the OP iframe the RP embeds as
  first-party and third-party-cookie policy never engages. `.test` is absent
  from the Public Suffix List, so `idp.test` and `rp.test` are different sites.
* **HTTPS.** The OP session cookie has to be `SameSite=None`; browsers only
  honour that alongside `Secure`; and `Secure` needs a secure context. Over
  plain HTTP the cookie would be withheld from the iframe in *every* engine and
  the comparison would prove nothing.

To run it locally:

```bash
echo "127.0.0.1 idp.test rp.test" | sudo tee -a /etc/hosts
python -m playwright install firefox
tox -e e2e -- -m spec_browser_cross_site
```

Without the hosts entries the layer skips — or fails, under
`E2E_REQUIRE_BROWSER`, so CI cannot silently drop it.

## Layout

```
tests/e2e/
  conftest.py          # live-IdP fixture, RP client fixture, marker wiring
  compliance.py        # compliance-matrix reporting plugin
  constants.py         # client ids / secrets / users (mirror the fixtures)
  helpers/
    idp_process.py     # launch/teardown the real idp project (runserver, or uvicorn for TLS)
    rp_process.py      # launch/teardown the SvelteKit rp + browser resolution
    tls.py             # throwaway self-signed cert for the cross-site layer
    local_http.py      # readiness polling for the local servers
    oauth_client.py    # Python relying-party (login/consent forms, token, ...)
    http_forms.py      # stdlib HTML form parsing
    jwt_tools.py       # ID Token / JWKS validation (OIDC Core 3.1.3.7)
  rfc6749_authorization_code/   rfc6749_client_credentials/
  rfc6749_resource_owner_password/  rfc6749_implicit/  rfc6749_refresh_token/
  rfc7636_pkce/  rfc7009_revocation/  rfc7662_introspection/
  rfc8414_as_metadata/  rfc8628_device_grant/
  rfc7591_dynamic_client_registration/
  cimd_client_id_metadata_document/   # CIMD-enabled IdP + loopback document server
  oidc_core/  oidc_discovery/  oidc_rp_initiated_logout/
  browser_rp/          # Playwright over the real SvelteKit RP (localhost, Chromium)
  browser_cross_site/  # Chromium + Firefox over idp.test / rp.test (HTTPS)
```

## Test clients

Beyond the two shipped demo clients (`seed.json`), the suite adds one client per
grant type via `tests/app/idp/fixtures/e2e_seed.json` (a confidential
authorization-code client requiring consent, a public PKCE-required client,
client-credentials, password, implicit, and hybrid clients) plus a claims-rich
`e2euser`. The IdP is launched with an expanded `SCOPES` set
(`read`/`write`/`email`/`profile`/`introspection`) via the environment variables
it already reads, so no provider defaults change for maintainers running the app
by hand.

The CIMD package registers no fixture clients: its clients *are* metadata
documents, served from a per-session loopback HTTP server and fetched by a
dedicated IdP instance launched with `CIMD_ENABLED` and the demo project's
`idp.cimd.LoopbackMetadataFetcher` (the production fetcher refuses loopback
addresses and requires CA-verified TLS, so it cannot run self-contained).

## Compliance matrix

Each run writes `compliance-matrix.md` and `compliance-matrix.json` (plus
`junit-e2e.xml`) to `$COMPLIANCE_MATRIX_DIR` (default `tests/e2e/reports/`),
mapping *specification → section → requirement → test → status*. The report also
lists specification features django-oauth-toolkit does **not** implement (PAR,
DPoP, mTLS, form_post, etc.) so the coverage boundary is explicit. In CI the
matrix is uploaded as the `oauth-oidc-compliance-matrix` artifact.
