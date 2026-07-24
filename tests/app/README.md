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