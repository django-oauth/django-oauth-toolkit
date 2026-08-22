# Test Apps

These apps are for local end to end testing of DOT features. They were implemented to save maintainers the trouble of setting up
local test environments. You should be able to start both and instance of the IDP and RP using the directions below, then test the
functionality of the IDP using the RP.

The IDP seed data includes a Device Authorization OAuth application as well.

## /tests/app/idp

This is an example IDP implementation for end to end testing. There are pre-configured fixtures which will work with the sample RP.

username: superuser
password: password

### Development Tasks

* starting up the idp

  ```bash
  cd tests/app/idp
  # create a virtual env if that is something you do
  python manage.py migrate
  python manage.py loaddata fixtures/seed.json
  python manage.py runserver
  # open http://localhost:8000/admin

  ```

* update fixtures

  You can update data in the IDP and then dump the data to a new seed file as follows.

```
python -Xutf8 ./manage.py dumpdata -e sessions  -e admin.logentry -e auth.permission -e contenttypes.contenttype -e oauth2_provider.accesstoken  -e oauth2_provider.refreshtoken -e oauth2_provider.idtoken --natural-foreign --natural-primary --indent 2 > fixtures/seed.json
```

### Device Authorization example

For testing out the device authorization flow, we don't really need a RP, as the device itself
is the "relying party". The seed data includes a Device Authorization Application, meaning
you could directly start the device authorization flow using `curl`. In the real world, the device
would be sending these request that we send here with `curl`.

_Note:_ you can find these `curl` commands in the Tutorial section of the documentation as well.

```sh
# Initiate device authorization flow on the device; here we use the client_id
# of the Device Authorization App from the seed data.
curl --location 'http://127.0.0.1:8000/o/device-authorization/' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=Qg8AaxKLs1c2W3PR70Sv5QxuSEREicKUlf83iGX3'
```

Follow the `verification_uri` from the response (should be similar to http://127.0.0.1:8000/o/device"),
enter the user code, approve, and then send another `curl` command to get the token.

```sh
curl --location 'http://localhost:8000/o/token/' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'device_code={the device code from the device-authorization response}' \
    --data-urlencode 'client_id=Qg8AaxKLs1c2W3PR70Sv5QxuSEREicKUlf83iGX3' \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code'
```

The response should include the access token.

### RFC 7523 private_key_jwt example

The seed data includes an "RFC 7523 private_key_jwt demo" application
(`client_id=private-key-jwt-demo`, client-credentials grant) whose registered `client_jwks`
holds the public half of the demo keypair below. Like the IDP's own `OIDC_RSA_PRIVATE_KEY`
default, this is example data for local testing, not a credential.

The RP has a ready-made "RFC 7523 private_key_jwt" tab that runs this exchange for you; the
equivalent by hand is:

```sh
cd tests/app/idp

# 1. Sign a client assertion with the demo key (fresh jti per call).
#    django.setup() configures settings for the import; unlike "manage.py shell"
#    it prints no banner, so the variable captures only the assertion.
ASSERTION=$(DJANGO_SETTINGS_MODULE=idp.settings python -c "
import django; django.setup()
from oauth2_provider.client import make_client_assertion
from jwcrypto import jwk
key = jwk.JWK(**{
    'kty': 'EC', 'crv': 'P-256', 'kid': 'demo-rp-key',
    'x': 'tS3tFvO_rzqp4FW4XU0M8agahChhDCxvfwkAOUf0r1w',
    'y': 'RXB1hhJu-vYd1Go5VyQ5gcQcxnNmCaCmE05mBrJ1qM4',
    'd': '0QcXCEERHRwHs1XiJFmnzvTwac93g6tFjwl39dwnWv4',
})
print(make_client_assertion(
    'private-key-jwt-demo', key, 'http://127.0.0.1:8000/o/token/',
))")

# 2. Exchange it for an access token — no client secret anywhere.
curl --location 'http://127.0.0.1:8000/o/token/' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
    --data-urlencode "client_assertion=$ASSERTION"
```

Replaying the same assertion is rejected (`invalid_client`): the `jti` is single-use.

To use your own key instead, generate one and register its public half:

```sh
python -c "
import os
os.umask(0o077)
from jwcrypto import jwk
key = jwk.JWK.generate(kty='EC', crv='P-256', kid='my-demo-key')
open('/tmp/demo-key.pem', 'wb').write(key.export_to_pem(private_key=True, password=None))
open('/tmp/demo-key.pub.json', 'w').write(key.export_public())
"
python manage.py shell -c "
from oauth2_provider.models import get_application_model
app = get_application_model().objects.get(client_id='private-key-jwt-demo')
app.client_jwks = '{\"keys\": [%s]}' % open('/tmp/demo-key.pub.json').read()
app.save()
"
```

### Pushed Authorization Request (PAR) example

The IDP serves the RFC 9126 PAR endpoint at `/o/par/` out of the box (it is advertised as
`pushed_authorization_request_endpoint` in `/.well-known/oauth-authorization-server`). Using the
seeded public "OIDC - Authorization Code" application, push an authorization request (a public
client authenticates with PKCE rather than a secret):

```sh
curl --location 'http://127.0.0.1:8000/o/par/' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm' \
    --data-urlencode 'response_type=code' \
    --data-urlencode 'redirect_uri=http://localhost:5173' \
    --data-urlencode 'scope=openid' \
    --data-urlencode 'state=some_state' \
    --data-urlencode 'code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM' \
    --data-urlencode 'code_challenge_method=S256'
```

The response is a `201` carrying a single-use `request_uri`, e.g.

```json
{"request_uri": "urn:ietf:params:oauth:request_uri:...", "expires_in": 60}
```

Then open the authorization endpoint in a browser with only the `client_id` and `request_uri`
(the code verifier for the `code_challenge` above is
`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`, used later at the token endpoint):

```
http://127.0.0.1:8000/o/authorize/?client_id=2EIxgjlyy5VgCp2fjhEpKLyRtSMMPK0hZ0gBpNdm&request_uri=urn:ietf:params:oauth:request_uri:...
```

## /test/app/rp

This is an example RP. It is a SPA built with Svelte.

### Development Tasks

* starting the RP

  ```bash
  cd test/apps/rp
  npm install
  npm run dev
  # open http://localhost:5173
  ```

The RP has four tabs: the OIDC Authorization Code flow, the Device Authorization
flow, **RFC 7523 private_key_jwt**, and **Pushed Authorization Requests (PAR)**.

### Pushed Authorization Requests (PAR) demo

The `/par` tab demonstrates RFC 9126 with a SvelteKit **server** component
(`src/routes/par/+page.server.ts`). Because PAR is a back-channel flow, the push
must happen server-side: the SvelteKit server (never the browser) holds the
client secret for the confidential `par-demo-confidential` seed application and
POSTs the authorization request to the IdP's `/o/par/` endpoint, receiving a
single-use `request_uri`. Only `client_id` + `request_uri` then travel through
the browser to the authorization endpoint. The demo IdP requires PKCE, so the
server also generates the PKCE verifier/challenge.

Start both the IdP (`http://localhost:8000`, with `fixtures/seed.json` loaded)
and the RP, open `http://localhost:5173/par`, and click **Push authorization
request**. You'll see the returned `request_uri`; continue to the authorization
endpoint (log in as `superuser` / `password` and approve), and the RP server
exchanges the returned code for tokens. This flow is covered end-to-end by
`tests/e2e/browser_rp/test_browser_par.py`.

### OIDC Back-Channel Logout demo

The IdP has back-channel logout enabled (`OIDC_BACKCHANNEL_LOGOUT_ENABLED`), and the
"OIDC - Authorization Code" seed application registers the RP's endpoint as its
`backchannel_logout_uri`. When a session ends at the IdP, DOT signs a logout token and
POSTs it to that URL — the RP is notified directly, without the browser being involved.

Since the OP talks to the RP's *server* while the session lives in the *browser*, the RP
demo bridges the two: `src/routes/api/backchannel-logout/+server.js` verifies the logout
token against the IdP's JWKS, and pushes an event over Server-Sent Events
(`src/routes/api/logout-events/+server.js`) to the tab holding that session, where
`src/components/OidcBackchannelLogoutHandler.svelte` clears the user. DOT does not issue a
`sid` claim yet, so the demo keys sessions on `sub`.

To try it, start the IdP and the RP, open `http://localhost:5173`, and log in. Then end the
session from the IdP side rather than the RP's Logout button — follow the **IDP Admin** link
and log out of `http://localhost:8000/admin`. The RP tab logs itself out on its own.

Because the logout token arrives as a cross-origin form POST, `svelte.config.js` adds the
IdP's origin to SvelteKit's `csrf.trustedOrigins`. The RP's back-channel endpoint and the
IdP's JWKS URL are hardcoded to the default `http://localhost:5173` / `http://localhost:8000`
addresses, so the demo assumes both apps are on their default ports.

## Running with Docker Compose

The repository root ships a `Dockerfile` and `docker-compose.yml` that build the
IDP into a self-contained image suitable both for local end-to-end testing and
for distribution as an easy-to-deploy IDP.

```bash
docker compose up --build
# open http://localhost:8000
```

### Static files

Static assets (Django admin, `oauth2_provider`) are collected into the image at
build time and served by [WhiteNoise](https://whitenoise.readthedocs.io/) from
gunicorn, so no reverse proxy or extra container is required. Because static
lives inside the image, it is always rebuilt fresh and never goes stale when a
named `/data` volume is reused across upgrades.

### Overriding templates

The image bundles default templates and also searches an optional override
directory mounted at `/templates` *before* the bundled defaults. To customise a
page in the distributable image, mount a host directory (read-only) at
`/templates` containing files that mirror the template paths you want to shadow:

```bash
docker run -p 8000:80 -v "$PWD/my-templates:/templates:ro" django-oauth-toolkit/idp
```

For example, `my-templates/registration/login.html` overrides the login page.
With nothing mounted, the bundled defaults are used. See the commented `volumes`
block on the `idp` service in `docker-compose.yml` for the Compose equivalent.