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
tox -e openid-conformance-suite                                            # default plans
tox -e openid-conformance-suite -- --plan oidcc-config-certification-test-plan
tox -e openid-conformance-suite -- --keep                                  # leave the stack running
tox -e openid-conformance-suite -- --verbose                               # print waiver templates
```

`run.py` does the work:

1. Generates a throwaway self-signed certificate for the IdP hostname `dot-idp`. The suite
   requires an https issuer; it does not validate the certificate of the server under test.
2. `docker compose up --build` on `docker-compose.yml`: the suite's prebuilt images from
   `registry.gitlab.com/openid/conformance-suite` pinned to the suite version, MongoDB, and the IdP
   image built from this checkout (the root `Dockerfile`), served over TLS by gunicorn.
   `seed_idp.py` runs once inside the IdP container to create the test user and the two
   statically registered clients.
3. Downloads the suite's own CI runner (`scripts/run-test-plan.py` and its two helper modules)
   at the same tag, checks their SHA-256, and runs the plans with `config/dot-oidcc.json` and
   `expected-failures.json`.
4. Writes the runner's exported results plus `docker-compose.log` to `reports/` and tears the
   stack down. With `--keep` the stack stays up: the suite UI is at
   <https://localhost.emobix.co.uk:8443/> (a public hostname that resolves to 127.0.0.1) and the
   IdP at <https://127.0.0.1:9443/>.

The exit status is the runner's. It is non-zero for any failure or warning not listed in
`expected-failures.json`, for a listed failure that did not occur, and for a module that did not
run to completion.

## Plans

| Plan | Default | Notes |
|---|---|---|
| `oidcc-config-certification-test-plan` | yes | Discovery document checks only. |
| `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]` | yes | Authorization code flow: the Basic OP profile. |
| `oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]` | no | `config/dot-oidcc.json` already carries the logout browser steps; run it with `--plan`. |
| `oidcc-hybrid-...`, `oidcc-implicit-...`, `oidcc-dynamic-...` | no | Supported by the toolkit and worth adding once Basic is calibrated. |

Form Post, Session Management, Front-Channel/Back-Channel Logout, 3rd-party initiated login and
the FAPI profiles are out of reach until the toolkit implements those specifications.

## Configuration

`config/dot-oidcc.json` is a standard suite configuration:

* `server.discoveryUrl` points at `https://dot-idp/o/.well-known/openid-configuration` on the
  compose network.
* `client` / `client2` are the clients `seed_idp.py` registers, with the suite's redirect URIs
  for the `dot` alias: `https://localhost.emobix.co.uk:8443/test/a/dot/callback`, the same with
  the query component `?dummy1=lorem&dummy2=ipsum`, and `.../post_logout_redirect`.
* `browser` tells the suite's built-in browser how to drive the IdP: fill `id_username` /
  `id_password` on the Django login page, click the `allow` button on the consent and logout
  pages, and wait for the suite's own callback page.
* `override` adjusts that per module, in the same way the suite's own CI configuration does:
  the `prompt=login` and `max_age` modules screenshot the re-login prompt, and the modules that
  expect the OP to refuse a bad redirect URI wait for the toolkit's `Error:` page instead of a
  redirect.

Changing a template or URL in `tests/app/idp` can therefore break a browser step here; the
`docker-compose.log` in `reports/` and the suite's log-detail pages (linked from the runner
output) show which one.

## Waivers

`expected-failures.json` lists the deviations that are accepted, in the suite's own format: a
module name, a variant filter, a config filename glob, the failing condition class and whether
a `failure` or a `warning` is expected, plus a comment saying why. Run with `--verbose` to get a
ready-made entry for every unexpected failure. Add an entry only with a reason that would
survive review: a feature the toolkit does not implement, or something CI cannot do (key
rotation). A fix in `oauth2_provider` is the right response to everything else, and the
runner fails the build when a listed failure no longer happens, so stale waivers are caught.

## Upgrading the suite

`DEFAULT_SUITE_VERSION` in `run.py` pins both the images and the runner scripts to one
conformance-suite release tag; `--suite-version` or `OPENID_CONFORMANCE_SUITE_VERSION`
override it for a one-off run (unverified runner download). To move the pin, update the
version and the three SHA-256 values in `RUNNER_SCRIPTS`
(`curl -sSL https://gitlab.com/openid/conformance-suite/-/raw/<tag>/scripts/<name> | sha256sum`),
and the `IMAGE_TAG` defaults in `docker-compose.yml`, then re-run: new suite releases add and
tighten checks, so expect to revisit `expected-failures.json`.
