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