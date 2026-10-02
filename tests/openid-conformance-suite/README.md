# OpenID Foundation conformance suite

This directory runs the official [OpenID Conformance Suite](https://openid.net/certification/about-conformance-suite/)
against the `tests/app/idp` demo provider. These are the same test modules the OpenID Foundation
uses for OpenID Provider certification, run headlessly in Docker so that CI (the
`openid-conformance-suite` job) and maintainers get the same signal.

It is not a certification. Certifying still means running the hosted suite at
certification.openid.net and submitting the results, but a green run here makes that step a
formality.

## Running

Docker with `docker compose` v2 is required. From the repository root:

```bash
tox -e openid-conformance-suite                      # every plan, sequentially
tox -e openid-conformance-suite -- --plan basic      # one plan (repeatable)
tox -e openid-conformance-suite -- --list-plans      # the plan table
tox -e openid-conformance-suite -- --keep            # leave the stack running
tox -e openid-conformance-suite -- --verbose         # print waiver templates
```

`run.py` does the work:

1. Generates two throwaway self-signed certificates. One is for the IdP hostname `dot-idp`: the
   suite requires an https issuer, but does not validate the certificate of the server under test.
   The other is for the suite's own host, `localhost.emobix.co.uk`. It replaces the certificate in
   the suite's nginx image, and the IdP trusts it (see [The client's `jwks_uri`](#the-clients-jwks_uri)).
2. `docker compose up --build` on `docker-compose.yml`: the suite's prebuilt images from
   `registry.gitlab.com/openid/conformance-suite` pinned to the suite version, MongoDB, and the IdP
   image built from this checkout (the root `Dockerfile`), served over TLS by gunicorn.
   `seed_idp.py` runs once inside the IdP container to create the test user and a pair of
   statically registered clients per grant type.
3. Downloads the suite's own CI runner (`scripts/run-test-plan.py` and its two helper modules)
   at the same tag, checks their SHA-256, and runs the plans with their `config/*.json` and the
   plan's calibration files under `expected/`.
4. Writes the runner's exported results plus `docker-compose.log` to `reports/` and tears the
   stack down. With `--keep` the stack stays up: the suite UI is at
   <https://localhost.emobix.co.uk:8443/> (a public hostname that resolves to 127.0.0.1) and the
   IdP at <https://127.0.0.1:9443/>.

The exit status is the runner's. It is non-zero for any failure or warning not listed in the
plan's `expected/<name>.failures.json`, for a module skipped without an entry in
`expected/<name>.skips.json`, for a listed failure or skip that did not occur, and for a module
that did not run to completion.

## Plans

`PLANS` in `run.py` maps a short name to a certification plan and the configuration file it
runs with. CI runs one matrix job per name, each with its own stack, so a plan's failure is
visible on its own and the jobs run in parallel.

Every plan gates the merge through the `Test successful` check. A plan whose modules cannot run
to completion, which leaves nothing to baseline, can be marked `optional` in the workflow matrix's
`include` list until they do; none is at present. Each plan's known toolkit gaps are recorded in
its baseline (see [Baseline and waivers](#baseline-and-waivers)), so a new failure or warning
anywhere fails CI, and so does a fixed one until its entry is removed. Every job also writes the
runner's totals to its summary and uploads the full report.

The plan names are the OpenID Provider certification profiles, which are named after the
OpenID Connect flow they test rather than the OAuth grant:

| Name | Plan | Flow (`response_type`) | Clients |
|---|---|---|---|
| `config` | `oidcc-config-certification-test-plan` | none: discovery document and JWKS | static |
| `basic` | `oidcc-basic-certification-test-plan` | Authorization Code (`code`) | static |
| `implicit` | `oidcc-implicit-certification-test-plan` | Implicit (`id_token`, `id_token token`) | static |
| `hybrid` | `oidcc-hybrid-certification-test-plan` | Hybrid (`code id_token`, `code token`, `code id_token token`) | static |
| `basic-dcr` | `oidcc-basic-certification-test-plan` | Authorization Code (`code`) | RFC 7591 |
| `implicit-dcr` | `oidcc-implicit-certification-test-plan` | Implicit (`id_token`, `id_token token`) | RFC 7591 |
| `hybrid-dcr` | `oidcc-hybrid-certification-test-plan` | Hybrid (`code id_token`, `code token`, `code id_token token`) | RFC 7591 |
| `dynamic` | `oidcc-dynamic-certification-test-plan` | Authorization Code (`code`), `private_key_jwt` clients | RFC 7591 |
| `rp-initiated-logout` | `oidcc-rp-initiated-logout-certification-test-plan` | Authorization Code (`code`), then logout | static |
| `rp-initiated-logout-dcr` | `oidcc-rp-initiated-logout-certification-test-plan` | Hybrid (`code id_token`), then logout | RFC 7591 |

The static-client plans run with `client_secret_basic` and, for the code-based flows, also
`client_secret_post`. "Static" clients are the pairs `seed_idp.py` registers; "RFC 7591" means the suite registers
its own through the toolkit's dynamic client registration endpoint, which the demo IdP leaves
open (`AllowAllDCRPermission`). That is why the Basic, Implicit and Hybrid plans run twice: the
second run exercises registration as well as the flow.

Some modules are expected to expose gaps in the toolkit rather than in the harness, and are
in the matrix for exactly that reason.

A module that does not run to completion counts toward the runner's circuit breaker
(`CONFORMANCE_MAX_CONSECUTIVE_FAILURES`, set to 25 by `run.py` so one gap does not hide the
rest of the plan's report).

Form Post, Session Management, Front-Channel/Back-Channel Logout, 3rd-party initiated login and
the FAPI profiles are out of reach until the toolkit implements those specifications. The
suite has no OpenID Connect plans for the toolkit's OAuth-only features (device grant,
introspection, revocation, PAR, resource indicators); those stay covered by `tests/e2e`.

## Configuration

`config/generate.py` writes the suite configuration files; edit the script and re-run it
rather than the JSON. An Application serves exactly one grant type, so each static-client plan
gets the seeded pair for its grant: `config/dot-oidcc.json` (alias `dot`, authorization code),
`config/dot-oidcc-implicit.json` (alias `dot-implicit`) and `config/dot-oidcc-hybrid.json`
(alias `dot-hybrid`); `config/dot-oidcc-dcr.json` (alias `dot-dcr`) is for the dynamically
registered plans. All are standard suite configurations:

* `server.discoveryUrl` points at `https://dot-idp/o/.well-known/openid-configuration` on the
  compose network.
* `client` / `client2` are either the clients `seed_idp.py` registers, with the suite's redirect
  URIs for the alias (`https://localhost.emobix.co.uk:8443/test/a/<alias>/callback`, the same
  with the query component `?dummy1=lorem&dummy2=ipsum`, and `.../post_logout_redirect`), or
  just a `client_name` for the suite to register itself.
* `browser` tells the suite's built-in browser how to drive the IdP: fill `id_username` /
  `id_password` on the Django login page, click the `allow` button on the consent and logout
  pages, and wait for the suite's own callback page.
* `override` adjusts that per module, in the same way the suite's own CI configuration does:
  the `prompt=login` and `max_age` modules screenshot the re-login prompt, the modules that
  expect the OP to refuse a bad redirect URI or logout request wait for the toolkit's `Error:`
  page instead of a redirect, and the logout modules without a `post_logout_redirect_uri` wait
  for the IdP home page the toolkit sends the End-User to.

Changing a template or URL in `tests/app/idp` can therefore break a browser step here; the
`docker-compose.log` in `reports/` and the suite's log-detail pages (linked from the runner
output) show which one.

## Baseline and waivers

`expected/<name>.failures.json` and `expected/<name>.skips.json` hold, per plan, the deviations
the runner accepts, in the suite's own format: a module name, a variant filter, a config filename
glob, and for failures the failing condition class, whether a `failure` or a `warning` is
expected, and a comment saying why. Skips name the modules the suite skips because the OP does
not support what they test (unsigned ID tokens, for one). The files are per plan because the
runner fails a run whose entries match no module it ran.

The failures files hold two kinds of entry:

* **Baseline** entries (`"baseline": true`) record the toolkit's known conformance gaps, one per
  failing module, variant, block and condition. They turn each plan into a ratchet: the runner
  fails the build for a failure or warning that is not listed, so a regression cannot land, and
  for a listed one that no longer happens, so a fix must also delete its entries and the diff
  shows exactly which gaps it closed. `baseline.py` writes them from a runner log; never edit
  them by hand.
* **Waivers** (no `baseline` key) are hand-written, each with a reason that would survive review:
  a feature the toolkit does not implement on purpose, or something CI cannot do (rotating the
  OP's signing key; see [What CI cannot satisfy](#what-ci-cannot-satisfy)). `baseline.py` keeps
  them.

To update a plan's baseline after a change that moves it, take the runner output (in CI, the
job's `runner.log` artifact or its log; locally, the terminal output), regenerate, and commit the
diff with the change:

```sh
python tests/openid-conformance-suite/baseline.py basic path/to/runner.log
```

The log comes from a run against the current file, so `baseline.py` keeps each baseline entry the
runner still reports as expected, drops each one it no longer reports (a fixed gap, listed under
"Expected failure did not happen") and adds each unexpected failure or warning.

Run with `--verbose` to get a ready-made entry for a single unexpected failure instead.

## What CI cannot satisfy

The `dynamic` plan carries the only waiver. CI runs `oidcc-server-rotate-keys`, but cannot
satisfy its `VerifyNewJwksHasNewSigningKey` condition, so that condition is waived. It does not
cover a toolkit gap, and the manual step [below](#rotating-the-signing-key) passes it.

### Rotating the signing key

`oidcc-server-rotate-keys` fetches the OP's JWKS when the module is created, waits for the tester
to rotate the signing key and press **Start**, then fetches the JWKS again. It expects the second
set to contain a new key (a failure if not) and still contain the old one (a warning if not). The
suite's runner presses Start as soon as the module is ready. It has no hook to run anything in
between, so CI cannot rotate the key there, and the suite's own CI waives the condition in the same
way. The module's description says that an OP which cannot rotate during the test self-asserts key
rotation in its certification attestation.

The demo IdP can rotate, which is an IdP restart with a new `OIDC_RSA_PRIVATE_KEY` and the old
key in `OIDC_RSA_PRIVATE_KEYS_INACTIVE`. `docker-compose.rotate-keys.yml` recreates `dot-idp` that
way. To pass the module by hand:

1. Run the plan with the stack kept up: `tox -e openid-conformance-suite -- --plan dynamic --keep`.
2. Open the plan in the suite UI (any log-detail link the runner printed leads to it) and run
   `oidcc-server-rotate-keys` again. It waits for you to press **Start**.
3. From `tests/openid-conformance-suite/`, write the current key and a new one to `.certs/`, then
   recreate the IdP with them:

   ```sh
   docker compose exec -T dot-idp python -c \
     'from idp import settings; print(settings.OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"].strip())' \
     > .certs/original-key.pem
   openssl genrsa -out .certs/rotated-key.pem 2048
   chmod 644 .certs/original-key.pem .certs/rotated-key.pem
   docker compose -f docker-compose.yml -f docker-compose.rotate-keys.yml up -d --no-deps --force-recreate dot-idp
   ```

   `--force-recreate` matters on a retry: Compose otherwise keeps a container whose configuration
   has not changed, and the running IdP would go on serving the keys it loaded at startup.

   Wait until the JWKS at <https://127.0.0.1:9443/o/.well-known/jwks.json> lists two `kid`s:
   the module fetches it once on **Start** and fails if the IdP is not answering yet.
4. Press **Start**. Both `VerifyNewJwks*` conditions pass.
5. `docker compose down --volumes` when done. To go back to the original key and keep the stack
   up, run the last command of step 3 again without `-f docker-compose.rotate-keys.yml`.

## The client's `jwks_uri`

`oidcc-registration-jwks-uri` and `oidcc-refresh-token-rp-key-rotation` register a
`private_key_jwt` client whose `jwks_uri` is on the suite's own host,
`https://localhost.emobix.co.uk:8443/...`, and the IdP has to fetch it to verify the client's
assertions. Inside the compose network two things would stop that fetch, and the stack deals with
both:

* The host resolves to a private compose address, which the library's SSRF guard refuses.
  `docker-compose.yml` sets `CLIENT_ASSERTION_JWKS_FETCHER` to the demo IdP's test-only
  `idp.client_assertions.PrivateHostJWKSFetcher`. It lets the hosts in `JWKS_URI_PRIVATE_HOSTS`,
  here only the suite's host, resolve to private addresses, and sends every other host through the
  default fetcher. It still requires `https`, verifies the certificate, refuses redirects and
  applies the default size and content checks.
* The suite's nginx image serves a self-signed certificate for `CN=localhost` only. `run.py` mints
  one for `localhost.emobix.co.uk`, `docker-compose.yml` mounts it over the image's, and the IdP
  trusts it through `SSL_CERT_FILE`.

Both live in the conformance stack only. "Custom outbound fetchers" in the docs
(`docs/advanced_topics.rst`) lists what a production fetcher must keep doing.

## Upgrading the suite

`DEFAULT_SUITE_VERSION` in `run.py` pins both the images and the runner scripts to one
conformance-suite release tag; `--suite-version` or `OPENID_CONFORMANCE_SUITE_VERSION`
override it for a one-off run (unverified runner download). To move the pin, update the
version and the three SHA-256 values in `RUNNER_SCRIPTS`
(`curl -sSL https://gitlab.com/openid/conformance-suite/-/raw/<tag>/scripts/<name> | sha256sum`),
and the `IMAGE_TAG` defaults in `docker-compose.yml`, then re-run: new suite releases add and
tighten checks, so expect to revisit the files under `expected/`.
