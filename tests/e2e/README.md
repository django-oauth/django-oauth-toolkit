# OAuth 2.0 / OpenID Connect End-to-End Compliance Suite

This suite exercises **every OAuth 2.0 / OpenID Connect flow that
django-oauth-toolkit supports**, end-to-end and black-box, against the real
demo apps in `tests/app/`:

* **`tests/app/idp`** — the toolkit configured as a live OAuth2/OIDC provider.
  It is booted as an actual `runserver` process (not imported in-process), so
  the tests talk to it purely over HTTP/HTML the way a real client would.
* **`tests/app/rp`** — the SvelteKit relying party, driven through Chromium with
  Playwright for the browser layer.

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
(as the CI job does) to make a missing/broken Chromium a hard failure instead of
a skip, so the browser RP coverage cannot be silently dropped.

## Layout

```
tests/e2e/
  conftest.py          # live-IdP fixture, RP client fixture, marker wiring
  compliance.py        # compliance-matrix reporting plugin
  constants.py         # client ids / secrets / users (mirror the fixtures)
  helpers/
    idp_process.py     # launch/teardown the real idp project
    rp_process.py      # launch/teardown the SvelteKit rp + Chromium resolution
    oauth_client.py    # Python relying-party (login/consent forms, token, ...)
    http_forms.py      # stdlib HTML form parsing
    jwt_tools.py       # ID Token / JWKS validation (OIDC Core 3.1.3.7)
  rfc6749_authorization_code/   rfc6749_client_credentials/
  rfc6749_resource_owner_password/  rfc6749_implicit/  rfc6749_refresh_token/
  rfc7636_pkce/  rfc7009_revocation/  rfc7662_introspection/
  rfc8414_as_metadata/  rfc8628_device_grant/
  rfc7591_dynamic_client_registration/
  oidc_core/  oidc_discovery/  oidc_rp_initiated_logout/
  browser_rp/          # Playwright over the real SvelteKit RP
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

## Compliance matrix

Each run writes `compliance-matrix.md` and `compliance-matrix.json` (plus
`junit-e2e.xml`) to `$COMPLIANCE_MATRIX_DIR` (default `tests/e2e/reports/`),
mapping *specification → section → requirement → test → status*. The report also
lists specification features django-oauth-toolkit does **not** implement (PAR,
DPoP, mTLS, form_post, etc.) so the coverage boundary is explicit. In CI the
matrix is uploaded as the `oauth-oidc-compliance-matrix` artifact.
