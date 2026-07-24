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
(`client_id=private-key-jwt-demo`, client-credentials grant). No private key ships with the
repository: generate your own keypair locally and register its public half on the application
first.

```sh
cd tests/app/idp

# 1. Generate a fresh keypair; the private key stays local.
python -c "
from jwcrypto import jwk
key = jwk.JWK.generate(kty='EC', crv='P-256', kid='my-demo-key')
open('/tmp/demo-key.pem', 'wb').write(key.export_to_pem(private_key=True, password=None))
open('/tmp/demo-key.pub.json', 'w').write(key.export_public())
"

# 2. Register the public half on the seeded demo application.
python manage.py shell -c "
from oauth2_provider.models import get_application_model
app = get_application_model().objects.get(client_id='private-key-jwt-demo')
app.client_jwks = '{\"keys\": [%s]}' % open('/tmp/demo-key.pub.json').read()
app.save()
"

# 3. Generate a signed client assertion (fresh jti per call) with the library helper.
ASSERTION=$(python -c "
from oauth2_provider.client_assertions import make_client_assertion
print(make_client_assertion(
    'private-key-jwt-demo',
    open('/tmp/demo-key.pem').read(),
    'http://localhost:8000/o/token/',
))")

# 4. Exchange it for an access token — no client secret anywhere.
curl --location 'http://localhost:8000/o/token/' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
    --data-urlencode "client_assertion=$ASSERTION"
```

Replaying the same assertion is rejected (`invalid_client`): the `jti` is single-use.

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