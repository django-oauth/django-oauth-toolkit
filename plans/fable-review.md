# django-oauth-toolkit — Security & Specification Code Review

**Reviewed commit:** `74b1006` (branch `claude/django-oauth-toolkit-review-h5llqc`)
**Date:** 2026-07-04
**Scope:** The `oauth2_provider` package — validators, views/endpoints, models, OIDC,
settings, middleware, decorators, DRF integration, admin, and management commands.
**Reference specs:** RFC 6749 (OAuth 2.0), OAuth 2.1 draft, RFC 6750 (Bearer), RFC 7009
(Revocation), RFC 7519/7515 (JWT/JWS), RFC 7617 (Basic auth), RFC 7636 (PKCE), RFC 7662
(Introspection), RFC 8252 (Native apps), RFC 8628 (Device grant), RFC 9700 (OAuth Security
BCP), OpenID Connect Core / Discovery / RP-Initiated Logout.

## How to read this

Every finding was verified by reading the referenced source lines directly (not just
accepted from an automated pass). Severity reflects impact **and** the conditions required
to trigger it — several high-value findings are gated behind non-default settings or
require staff/DB access, and that is called out per finding. A list of things that were
checked and found **sound** is included at the end so this document doubles as a map of
what the library already does right.

Severity legend: **Critical** (immediate exploit, default config) · **High** (serious, may
need common non-default config or privileged position) · **Medium** (real weakness, often
opt-in or partial mitigation) · **Low** (hardening / robustness / spec conformance) ·
**Info** (design note, negligible direct risk).

---

## Summary

| # | Severity | Finding | Location | Category |
|---|----------|---------|----------|----------|
| H1 | High | Device-flow user codes generated with non-CSPRNG `random` | `utils.py:69` | Security / RFC 8628 |
| H2 | High | Client secret & Base64 Basic credentials written to logs | `oauth2_validators.py:178,208,151,157` | Security |
| H3 | High | Admin lists & searches plaintext access/refresh tokens and grant codes | `admin.py:33,36,41,43,55,58` | Security / Django |
| H4 | High | HS256 ID tokens signed with the *hashed* client secret (unverifiable) | `models.py:287` | OIDC / crypto |
| H5 | High | `rw_protected_resource` mutates a shared scope list across requests | `decorators.py:72,74` | Correctness |
| M1 | Medium | Token revocation does not verify the requesting client owns the token | `oauth2_validators.py:760` | RFC 7009 |
| M2 | Medium | Introspection discloses username/scope/client_id of any token to any introspection client | `introspect.py:44` | RFC 7662 |
| M3 | Medium | Introspection accepts the token in the GET query string | `introspect.py:58` | RFC 7662 / 9700 |
| M4 | Medium | Redirect-URI matching is subset-not-exact on the query component | `models.py:937` | OAuth 2.1 |
| M5 | Medium | Wildcard host match allows same-suffix hijack (`*example.com`→`evilexample.com`) | `models.py:907` | OAuth 2.1 |
| M6 | Medium | No `slow_down` / interval throttle on device token polling | `token.py:354` | RFC 8628 |
| M7 | Medium | Device confirm/status views not owner-scoped (IDOR via `user_code`) | `device.py:169,246` | Authorization |
| M8 | Medium | Insecure defaults (http redirects, 10h tokens, non-expiring refresh, implicit types) | `settings.py:63,83,92` | RFC 9700 / OAuth 2.1 |
| M9 | Medium | `WWW-Authenticate` values interpolated into quoted strings without escaping | `authentication.py:20` | CWE-113 |
| M10 | Medium | Access/refresh tokens and auth codes stored in plaintext at rest | `models.py:405,509,333` | Security / BCP |
| L1 | Low | Discovery omits RS256 (a MUST) when no RSA key configured | `oidc.py:77` | OIDC Discovery |
| L2 | Low | `plain` PKCE method advertised in discovery | `oidc.py:101` | OAuth 2.1 |
| L3 | Low | Missing `Cache-Control: no-store` on introspection & device error responses | `introspect.py`, `token.py` | RFC 6749 / 7662 |
| L4 | Low | Resource decorators return 403 (not 401 + `WWW-Authenticate`) for missing token | `decorators.py:35,83` | RFC 6750 |
| L5 | Low | Model `__str__` returns the raw token/code | `models.py:478,546,362` | Django / Security |
| L6 | Low | Multiple unguarded `DoesNotExist`/`KeyError` → HTTP 500 | several | Robustness |
| L7 | Low | `assert`/`assert False` used for control flow (stripped under `-O`) | `models.py:173`, `permissions.py:48` | Python |
| L8 | Low | Case-sensitive Basic/Bearer scheme checks | `oauth2_validators.py:115`, `middleware.py:38` | RFC 7617 / 6750 |
| L9 | Low | `client_secret` field carries a useless `db_index=True` | `models.py:141` | Django |
| L10 | Low | `log.exception` used for expected/normal conditions | `oauth2_validators.py:414`, `middleware.py:63` | Logging |
| L11 | Low | `createapplication --client-secret` passes secret via CLI arg | `createapplication.py:46` | CWE-214 |
| L12 | Low | `prompt=consent` / `select_account` ignored (silent auto-approval) | `base.py:156` | OIDC Core |
| L13 | Low | OIDC issuer scheme derived from client-influenceable header / Host | `settings.py:334`, `oidc.py:51` | OIDC |
| L14 | Low | `OAuthToolkitError` dereferences `None` when only `redirect_uri` passed | `exceptions.py:10` | Robustness |
| I1 | Info | Refresh-token reuse detection is opt-in; grace window replays same token | `oauth2_validators.py:824` | RFC 9700 |
| I2 | Info | `validate_user_match` unconditionally returns `True` (id_token_hint ignored) | `oauth2_validators.py:1023` | OIDC Core |
| I3 | Info | No `is_active` flag to suspend a compromised Application | `models.py:273` | Ops |
| I4 | Info | `unique_together=(token,revoked)` ineffective on NULL-distinct DBs | `models.py:549` | Django / DB |
| I5 | Info | Default scopes not validated ⊆ available; no per-application scope confinement | `scopes.py:37` | Hardening |
| I6 | Info | RP-logout ID token not validated for `aud`/`azp` | `oidc.py:204` | OIDC |
| I7 | Info | Some Grant lookups by `code` alone omit the `application` filter | `oauth2_validators.py:591,1047` | Defense-in-depth |
| I8 | Info | `cleartokens` ignores batch settings, emits no output, no error handling | `cleartokens.py:6` | Ops |
| I9 | Info | `validate_refresh_token` mutates request before client-match check | `oauth2_validators.py:833` | Hygiene |
| I10 | Info | `.first().token` can `AttributeError` on the reuse-grace path | `oauth2_validators.py:708` | Robustness |
| I11 | Info | `dotless_domain_re` accepts single-label/internal hostnames | `validators.py:12` | Format |
| I12 | Info | `revoke_token` scans unindexed `token` column; `MultipleObjectsReturned` uncaught | `oauth2_validators.py:778` | Django |
| I13 | Info | Basic-auth client-existence timing oracle | `oauth2_validators.py:166` | Timing |

---

## High

### H1 — Device-flow user codes use a non-cryptographic PRNG
**Severity:** High · **`oauth2_provider/utils.py:36-77`** (lines 69-75) · Security / RFC 8628 §5.1–5.2 / CWE-338

```python
import random
...
character_space = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
for i in range(user_code_length):
    user_code[i] = random.choice(character_space)
```

`user_code_generator` is the default `OAUTH_DEVICE_USER_CODE_GENERATOR`. It uses Python's
`random` module — the Mersenne-Twister PRNG — which is not cryptographically secure and is
predictable once enough outputs are observed. In the device grant the `user_code` is the
credential a user presents to bind a device session, and downstream views (`DeviceUserCodeView`,
`DeviceConfirmView`, `DeviceGrantStatusView`) look up grants **solely** by `user_code`. The
function's own docstring reasons about brute-force entropy, which makes the CSPRNG omission a
clear oversight. Combined with the missing rate-limit (M6) and the missing owner-scoping (M7),
predictable codes materially raise the risk of device-session hijack.

**Fix:** `import secrets` and use `secrets.choice(character_space)` (drop-in). Equivalently
`random.SystemRandom().choice`.

### H2 — Client secret and Basic-auth credentials logged in cleartext
**Severity:** High · **`oauth2_provider/oauth2_validators.py:178, 208, 151, 157`** · Security / RFC 9700 §2

```python
log.debug("Failed basic auth: wrong client secret %s" % client_secret)   # :178
log.debug("Failed body auth: wrong client secret %s" % client_secret)    # :208
log.debug("Failed basic auth: %r can't be decoded as base64", auth_string)  # :151 (auth_string = b64(id:secret))
```

On failed client authentication the plaintext `client_secret` is written to the log, and at
lines 151/157 the raw `auth_string` (Base64 of `client_id:client_secret`, trivially decoded) is
logged. DEBUG logging is routinely enabled in staging and during incident triage, so this is a
realistic path for password-equivalent client secrets to reach log files, aggregators, and SIEMs.

**Fix:** Never interpolate the secret or `auth_string`. Log the `client_id` only, e.g.
`log.debug("Failed basic auth: wrong client secret for client_id %s", client_id)`.

### H3 — Django admin lists and searches plaintext tokens and codes
**Severity:** High · **`oauth2_provider/admin.py:33, 36, 41, 43, 55, 58`** · Security / Django

```python
class AccessTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "user", "application", "expires")
    search_fields = ("token",) + (("user__email",) if has_email else ())
class GrantAdmin(admin.ModelAdmin):
    list_display = ("code", ...)
    search_fields = ("code",) + ...
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ("token", ...)
    search_fields = ("token",) + ...
```

Because access/refresh tokens and authorization codes are stored in cleartext (M10), these
columns are **live, usable bearer credentials**. Any staff user with view access to these
models sees tokens they can replay to impersonate users. `search_fields` is worse: it places
the secret into the `?q=` querystring, where it lands in web-server access logs and browser
history.

**Fix:** Remove `token`/`code` from `list_display` and `search_fields`. If a lookup handle is
needed, expose a masked/truncated read-only method (e.g. last 6 chars) that is not searchable;
search by `user__email`/`application` instead. `IDTokenAdmin` already does the right thing.

### H4 — HS256 ID tokens are signed with the hashed client secret
**Severity:** High (when OIDC + HS256 is used) · **`oauth2_provider/models.py:281-289`** · OIDC Core §16.19 / RFC 7515

```python
elif self.algorithm == AbstractApplication.HS256_ALGORITHM:
    return jwk.JWK(kty="oct", k=base64url_encode(self.client_secret))
```

For HS256 the JWS MAC key must be the shared `client_secret` octets that the relying party
also holds. But `client_secret` is stored hashed by default (`hash_client_secret=True`,
`models.py:143`, via `make_password`), and `clean()` never forces it off for HS256 apps.
So the server signs with the *password-hash string* (`pbkdf2_sha256$...`) as the HMAC key while
the RP has the *plaintext* secret — the RP can never verify the signature. Two problems: a silent
interop break, and cryptographic misuse of a password hash as a MAC key.

**Fix:** In `AbstractApplication.clean()`, require `hash_client_secret=False` when
`algorithm == HS256` (or raise `ImproperlyConfigured`); alternatively derive the HS256 key from
the plaintext secret captured at creation time. At minimum, document the constraint loudly.

### H5 — `rw_protected_resource` mutates a shared scope list on every request
**Severity:** High (correctness/availability) · **`oauth2_provider/decorators.py:55, 72, 74`** · Correctness

```python
def rw_protected_resource(scopes=None, ...):
    _scopes = scopes or []              # bound once, at decoration time
    def decorator(view_func):
        def _validate(request, *args, **kwargs):
            ...
            if request.method.upper() in ["GET", "HEAD", "OPTIONS"]:
                _scopes.append(oauth2_settings.READ_SCOPE)   # mutates the shared list
            else:
                _scopes.append(oauth2_settings.WRITE_SCOPE)
            valid, oauthlib_req = core.verify_request(request, scopes=_scopes)
```

`_scopes` is created once when the decorator is applied and then appended to on **every**
request. It grows without bound (`["read", "write", "read", ...]`). Since `verify_request`
requires *all* listed scopes, after the first write request the list contains both `read` and
`write`, so subsequent read-only requests with a read-only token start being rejected —
behavior becomes request-order-dependent and not thread-safe. If a caller passed a `scopes=`
list, that external list is mutated too.

**Fix:** Build a per-request list: `required = list(_scopes) + [read_or_write_scope]` and pass
`required` to `verify_request`; never mutate `_scopes`.

---

## Medium

### M1 — Revocation does not verify the token belongs to the requesting client
**Severity:** Medium · **`oauth2_provider/oauth2_validators.py:760-782`** · RFC 7009 §2.1

```python
token_type = token_types.get(token_type_hint, AccessToken)
try:
    token_type.objects.get(token=token).revoke()
except ObjectDoesNotExist:
    for other_type in [_t for _t in token_types.values() if _t != token_type]:
        list(map(lambda t: t.revoke(), other_type.objects.filter(token=token)))
```

RFC 7009 §2.1 requires the server to verify the token was issued to the client making the
revocation request and to refuse otherwise. Here the lookup ignores `request.client`, so any
client that authenticates at the revocation endpoint can revoke **another** client's token
merely by presenting its value — a cross-client denial-of-service.

**Fix:** Scope by owner: `token_type.objects.get(token=token, application=request.client)` (and
likewise in the fallback branch).

### M2 — Introspection leaks token metadata across clients
**Severity:** Medium · **`oauth2_provider/views/introspect.py:34-54`** · RFC 7662 §2.1/§4

Any caller holding a token with the `introspection` scope can introspect **any** access token
in the system and receives the resource owner's `username`, the owning `client_id`, the scope,
and the expiry. There is no check tying the introspected token to the caller's audience/ownership.
RFC 7662 §2.1 says the server SHOULD determine whether the requester is authorized to introspect
*this particular* token, and §4 warns against disclosing more than the requester needs — this is
a cross-client PII (username) and scope-enumeration disclosure.

**Fix:** Restrict results to tokens whose `application` is the requesting client (or a configured
resource-server/audience relationship); otherwise return `{"active": false}`. At minimum gate the
`username` field behind a setting.

### M3 — Introspection accepts the token in the URL query string
**Severity:** Medium · **`oauth2_provider/views/introspect.py:58-68`** · RFC 7662 §2.1 / RFC 9700 §2.4 / RFC 6750 §2.3

```python
def get(self, request, *args, **kwargs):
    # URL: https://example.com/introspect?token=mF_9.B5f-4.1JqM
    return self.get_token_response(request.GET.get("token", None))
```

RFC 7662 defines introspection over HTTP POST with parameters in the body. Accepting the token
via GET puts a live credential in the query string, where it is captured by access logs, proxies,
`Referer`, and browser history (RFC 6750 §2.3 / RFC 9700 §2.4 forbid tokens in URIs).

**Fix:** Make the endpoint POST-only (remove `get()`), or at least never read the token from the
query string.

### M4 — Redirect-URI matching is subset-not-exact on the query component
**Severity:** Medium · **`oauth2_provider/models.py:884-943`** (lines 936-938) · OAuth 2.1 §4.1.2.1 / RFC 9700 §2.1

```python
aqs_set = set(parse_qsl(parsed_allowed_uri.query))
if not aqs_set.issubset(uqs_set):
    continue  # circuit break
return True
```

Scheme, host, port, and path are matched exactly, but the registered query parameters need only
be a **subset** of the request's query. A request may therefore append arbitrary extra parameters
(e.g. `?next=//evil`) and still match. OAuth 2.1 and the Security BCP mandate exact redirect-URI
string comparison; the relaxed query match weakens the primary anti–open-redirect control and
enables parameter smuggling into the redirect target.

**Fix:** Require full equality of the query component (`aqs_set == uqs_set`) or normalized
full-URI equality; if the relaxed behavior is intentional, gate it behind an explicit setting and
document it.

### M5 — Wildcard host matching allows same-suffix domain hijack
**Severity:** Medium (opt-in; `ALLOW_URI_WILDCARDS` defaults off) · **`oauth2_provider/models.py:906-912`** · OAuth 2.1

```python
if oauth2_settings.ALLOW_URI_WILDCARDS and parsed_allowed_uri.hostname.startswith("*"):
    if not parsed_uri.hostname.endswith(parsed_allowed_uri.hostname[1:]):
        continue
```

Only the leading `*` is stripped, so a registered `*example.com` yields the suffix `example.com`
and `evilexample.com` matches (`endswith("example.com")` is true with no label boundary). It also
assumes `hostname` is non-`None` (a schemeless/hostless URI raises `AttributeError`). OAuth 2.1
forbids wildcard redirect URIs outright; even as an opt-in feature the matching is looser than the
syntax implies.

**Fix:** Require the wildcard to be a full label prefix (`*.`) and match only on label boundaries:
`host == suffix or host.endswith("." + suffix)`; reject bare `*suffix` forms; guard `hostname is
None`.

### M6 — No `slow_down` / interval throttle on device token polling
**Severity:** Medium · **`oauth2_provider/views/token.py:352-373`** · RFC 8628 §3.4–3.5

```python
# TODO: "slow_down" error (essentially rate-limiting).
if device.status == device.AUTHORIZATION_PENDING:
    error = rfc8628_errors.AuthorizationPendingError()
```

The device grant model carries `interval` (default 5s) and a `last_checked` timestamp, but the
token endpoint never enforces them and never emits `slow_down`. A client (or an attacker holding a
`device_code`) can poll arbitrarily fast, defeating the spec's built-in throttle and enabling
resource abuse. The inline TODO confirms it is unimplemented.

**Fix:** On each poll, compare `now - device.last_checked` to `device.interval`; if too fast,
return `rfc8628_errors.SlowDownError()` and increase the interval. Persist `last_checked` per poll.

### M7 — Device confirm/status views are not owner-scoped (IDOR)
**Severity:** Medium · **`oauth2_provider/views/device.py:161-223` (get_object 169-186), `239-251`** · Authorization

`DeviceConfirmView.get_object()` fetches the grant by `client_id` + `user_code` +
`status=AUTHORIZATION_PENDING` with **no** `user=request.user` filter, and `form_valid` flips the
status to `AUTHORIZED`/`DENIED` without confirming the acting user matches the user bound at
code-entry. `DeviceGrantStatusView.get_queryset()` returns `objects.all()`. So any authenticated
user who knows/guesses a `user_code` can approve, deny, or read the status of a device grant that
is not theirs. This compounds H1 (predictable codes) and M6 (no rate limit).

**Fix:** Scope `get_object()`/`get_queryset()` by `user=self.request.user` (404 otherwise) and
re-verify ownership before mutating status.

### M8 — Insecure-by-default settings
**Severity:** Medium · **`oauth2_provider/settings.py:63-67, 83, 92-100`** · RFC 9700 / OAuth 2.1

```python
"ACCESS_TOKEN_EXPIRE_SECONDS": 36000,   # 10 hours
"ID_TOKEN_EXPIRE_SECONDS": 36000,       # 10 hours
"REFRESH_TOKEN_EXPIRE_SECONDS": None,   # never expires
"REFRESH_TOKEN_REUSE_PROTECTION": False,
"ALLOWED_REDIRECT_URI_SCHEMES": ["http", "https"],   # http accepted
"OIDC_RESPONSE_TYPES_SUPPORTED": ["code", "token", "id_token", "id_token token",
                                  "code token", "code id_token", "code id_token token"],
```

Several defaults are looser than the current BCP:
- **10-hour** access/ID tokens widen the exploit window for a leaked bearer token.
- **Non-expiring** refresh tokens with **reuse protection off** mean a stolen refresh token grants
  indefinite access with no automatic breach detection (even though `ROTATE_REFRESH_TOKEN=True`).
- **`http`** redirect URIs are accepted by default, exposing codes/tokens to network attackers —
  and inconsistently, `ALLOWED_SCHEMES` already defaults to `["https"]`.
- Discovery advertises implicit/hybrid `token`-returning **response types** by default, which
  OAuth 2.1 removes and RFC 9700 §2.1.2 says SHOULD NOT be used.

`PKCE_REQUIRED=True` and `AUTHORIZATION_CODE_EXPIRE_SECONDS=60` are already good.

**Fix:** Lower default access/ID TTL (e.g. 300–3600s), set a finite default
`REFRESH_TOKEN_EXPIRE_SECONDS`, default `REFRESH_TOKEN_REUSE_PROTECTION=True`, default redirect
schemes to `["https"]`, and default `OIDC_RESPONSE_TYPES_SUPPORTED` to `["code"]` (plus
`id_token`/`code id_token` only where hybrid is genuinely needed).

### M9 — `WWW-Authenticate` header built without quoted-string escaping
**Severity:** Medium · **`oauth2_provider/contrib/rest_framework/authentication.py:16-20, 51-55`** · CWE-113 / RFC 7235 §2.1

```python
def _dict_to_string(self, my_dict):
    return ",".join(['{k}="{v}"'.format(k=k, v=v) for k, v in my_dict.items()])
...
oauth2_error = getattr(request, "oauth2_error", {})
www_authenticate_attributes.update(oauth2_error)
```

`oauth2_error` (e.g. `error_description`) can reflect request-derived data from oauthlib and is
interpolated into a `"..."` quoted-string with no escaping of `"` or `\`. A crafted value
containing a double quote breaks out of the quoted string and can forge additional auth-params
(bogus `realm`/`scope`) or confuse client parsers. Django's `BadHeaderError` blocks CR/LF but not
quotes.

**Fix:** Escape `"` and `\` per RFC 7235 quoted-string rules (and strip control chars) before
interpolation.

### M10 — Tokens and authorization codes stored in plaintext at rest
**Severity:** Medium (design; requires DB read to exploit) · **`oauth2_provider/models.py:405, 509, 333`** · RFC 9700 §4 / BCP

```python
token = models.TextField()                              # AccessToken (raw)
token_checksum = TokenChecksumField(..., unique=True)   # SHA-256, lookup only
token = models.CharField(max_length=255)                # RefreshToken (raw)
code = models.CharField(max_length=255, unique=True)    # Grant (raw)
```

Bearer credentials are password-equivalent, yet the raw `token`/`code` columns are persisted in
cleartext. The `token_checksum` (unsalted SHA-256) is used only for indexing and adds no
confidentiality. A read-only DB compromise (SQLi elsewhere, backup/replica leak) yields directly
replayable tokens and codes. This underpins H3.

**Fix:** Store only a keyed/salted digest and compare in constant time (the checksum already
provides an indexable lookup); drop or encrypt the plaintext column. If backward compatibility
requires the raw column, make plaintext storage opt-in and off by default, and document the
exposure.

---

## Low

### L1 — Discovery omits RS256 when no RSA key is set
**`oauth2_provider/views/oidc.py:77-79`** · OIDC Discovery §3. `id_token_signing_alg_values_supported`
MUST include `RS256`; when `OIDC_RSA_PRIVATE_KEY` is unset the list is `[HS256]` only, violating
the MUST and advertising a symmetric-only OP that public clients cannot use. Fix: always include
RS256 (and require an RSA key for a conforming OP) or document OIDC as unsupported without one.

### L2 — `plain` PKCE method advertised
**`oauth2_provider/views/oidc.py:101`** (`code_challenge_methods_supported` from
`AbstractGrant.CODE_CHALLENGE_METHODS`, `models.py:325`) · OAuth 2.1 §7.6 / PKCE BCP. Advertising
`plain` invites downgraded challenges that offer no protection if the request is observed. Fix:
advertise only `S256` (or make it configurable, defaulting to `S256`).

### L3 — Missing `Cache-Control: no-store` on introspection & device error responses
**`introspect.py:28-56`, `token.py:347-380`** · RFC 6749 §5.1 / RFC 7662 §4. The success token
paths copy oauthlib's `no-store` headers, but the introspection `JsonResponse`s and the hand-built
device error / `device_not_found` responses set no cache headers though they carry sensitive data.
Fix: set `response["Cache-Control"] = "no-store"` (and `Pragma: no-cache`) on those responses.

### L4 — Resource decorators return 403 instead of 401 + challenge
**`oauth2_provider/decorators.py:35, 83`** · RFC 6750 §3. A missing/invalid/expired bearer token
should yield `401` with `WWW-Authenticate: Bearer ... error="invalid_token"`, not a bare
`HttpResponseForbidden()`. Clients cannot distinguish "authenticate" from "forbidden," breaking
standard re-auth/refresh flows. Fix: 401 + challenge for auth failures; reserve 403 for
insufficient scope.

### L5 — Model `__str__` returns the raw token/code
**`oauth2_provider/models.py:478 (AccessToken), 546 (RefreshToken), 362 (Grant)`** · Django /
Security. `__str__` renders in the admin change list, in `repr()` inside tracebacks, and in
logging, so any such surface leaks a usable credential. `IDToken.__str__` (line 648) is correct.
Fix: return a non-sensitive identifier (`f"AccessToken #{self.pk}"` or a truncated checksum).

### L6 — Unguarded lookups that surface as HTTP 500
Robustness / RFC 6749 §5.2. Several `.get()`/dict-index calls on attacker-influenceable input
raise unhandled exceptions instead of a defined error:
- `views/base.py:117-119` — `Application.objects.get(client_id=...)` on the POSTed hidden field
  (tampered/deleted client → `DoesNotExist` → 500).
- `views/token.py:395-396` — `params["device_code"]` (`KeyError` when a device-code grant omits it).
- `views/device.py:39` — `request.POST["client_id"]` (`KeyError`).
- `views/oidc.py:345-350` — `get_request_application` (`Application.DoesNotExist` on unknown
  `client_id` during RP logout).
- `oauth2_validators.py:345, 580-585` — `Grant.objects.get(...)` in `confirm_redirect_uri` /
  `get_code_challenge[_method]` (contrast the correctly-guarded `validate_code`, line 509).

Fix: use `get_object_or_404` / `.get(...)` with `try/except` and return `invalid_request` /
`invalid_grant`.

### L7 — `assert` used for control-flow validation (stripped under `-O`)
**`oauth2_provider/models.py:173-177` (`assert False`), `contrib/rest_framework/permissions.py:48-52,
170-174`** · Python. Under `python -O`/`PYTHONOPTIMIZE` these asserts vanish: `default_redirect_uri`
would silently return `None` (feeding `None` into redirect logic), and `TokenHasScope` would fall
through a misconfiguration check. Fix: `raise ImproperlyConfigured(...)`.

### L8 — Case-sensitive Basic/Bearer scheme checks
**`oauth2_validators.py:115` (`auth_type != "Basic"`), `middleware.py:38, 56`
(`startswith("Bearer")`)** · RFC 7617 / RFC 6750 / RFC 9110. Auth-scheme tokens are
case-insensitive; the middleware's `startswith("Bearer")` also matches `Bearerfoo` and misses
`bearer `. Fix: `scheme, _, token = header.partition(" ")` then `scheme.lower() == "bearer"`
(and `auth_type.lower() != "basic"`).

### L9 — `client_secret` field has a useless `db_index=True`
**`oauth2_provider/models.py:136-142`** · Django. Because secrets are stored per-record-salted via
`make_password`, you can never look up by secret value, so the index is dead (pure write overhead)
and needlessly copies the credential column into index pages. Fix: drop `db_index=True`.

### L10 — `log.exception` for expected conditions
**`oauth2_validators.py:414-419` (non-200 introspection response), `middleware.py:63-64`
(`AccessToken.DoesNotExist`)** · Logging. `log.exception` outside an `except` (or for a normal
not-found) emits a phantom `NoneType: None` traceback at ERROR level; the middleware case lets an
attacker spraying random tokens flood logs. Fix: `log.error(...)` / `log.debug(...)` without the
traceback.

### L11 — `createapplication` accepts the client secret as a CLI argument
**`oauth2_provider/management/commands/createapplication.py:46-50`** · CWE-214. A `--client-secret`
value is visible via `ps`/`/proc` and shell history. (Autogenerated secrets are handled correctly.)
Fix: read from env var or stdin/`getpass`, or document the risk.

### L12 — `prompt=consent` / `select_account` ignored
**`oauth2_provider/views/base.py:156-158, 189-224`** · OIDC Core §3.1.2.1. Only `prompt=login` and
`prompt=none` are handled; `prompt=consent` is still silently auto-approved via
`skip_authorization` or the `approval_prompt=auto` prior-token path, so an RP cannot force a fresh
consent screen. Fix: honor `prompt=consent` by bypassing auto-approval and always rendering the
consent form.

### L13 — OIDC issuer scheme derived from client-influenceable input
**`oauth2_provider/settings.py:334-336` (`X_DJANGO_OAUTH_TOOLKIT_SECURE` header),
`views/oidc.py:51-63` (Host-header-derived endpoints)** · OIDC Core §2 / Discovery. The `issuer` is
a security-critical identifier RPs validate `iss` against; deriving its scheme/host from request
headers risks host-header poisoning when `ALLOWED_HOSTS` is lax. Mitigated by setting
`OIDC_ISS_ENDPOINT` explicitly. Fix: recommend/require a fixed `OIDC_ISS_ENDPOINT`; document strict
`ALLOWED_HOSTS` and trusted-proxy handling of the secure header.

### L14 — `OAuthToolkitError` dereferences `None` when only `redirect_uri` is passed
**`oauth2_provider/exceptions.py:6-11`** · Robustness. `self.oauthlib_error.redirect_uri = ...`
raises `AttributeError` if constructed with a `redirect_uri` but no `error`, masking the original
condition and potentially turning a handled OAuth error into a 500. Fix:
`if redirect_uri and self.oauthlib_error is not None:`.

---

## Informational

- **I1 — Refresh-token reuse detection is opt-in.** `oauth2_validators.py:824-831`. With the
  default `REFRESH_TOKEN_REUSE_PROTECTION=False`, replay of a rotated/revoked refresh token fails
  but does not invalidate the token family; within the grace window a replayed token is even
  accepted and returns the same access token. RFC 9700 §4.14.2 recommends automatic reuse detection
  with family invalidation. Consider defaulting it on (see M8).
- **I2 — `validate_user_match` always returns `True`.** `oauth2_validators.py:1023-1027`. OIDC
  `id_token_hint` is not validated against the authenticated user; acceptable only if deployments
  never rely on `id_token_hint` semantics. Implement or document.
- **I3 — No `is_active` flag on Application.** `models.py:273-279` (`is_usable` always `True`). A
  compromised client can only be stopped by deletion (cascading). Add an enabled flag honored by
  `is_usable`.
- **I4 — `unique_together=("token","revoked")` is ineffective on NULL-distinct databases.**
  `models.py:549-554`. On PostgreSQL, multiple rows with the same `token` and `revoked IS NULL`
  coexist, so "active token uniqueness" relies solely on randomness. Use a conditional
  `UniqueConstraint(condition=Q(revoked__isnull=True))`.
- **I5 — Scope backend does not validate defaults ⊆ available, nor confine scopes per app.**
  `scopes.py:37-45`. Any client can request any globally-defined scope. Validate
  `_DEFAULT_SCOPES ⊆ _SCOPES` at startup and document that per-app confinement needs a custom
  backend.
- **I6 — RP-logout ID token not validated for `aud`/`azp`.** `oidc.py:204-215` only checks `iss`;
  with `OIDC_RP_INITIATED_LOGOUT_ACCEPT_EXPIRED_TOKENS` (default `True`) `exp`/`nbf` are skipped.
  Signature and (when supplied) `client_id` match are checked, so risk is low, but validation is
  weaker than at authentication. Validate `aud`/`azp` against the resolved application.
- **I7 — Some Grant lookups omit the `application` filter.** `oauth2_validators.py:591, 1047`
  (`get_authorization_code_scopes`, `get_authorization_code_nonce`) match by `code` alone, unlike
  sibling methods. Harmless given code entropy/single-use, but inconsistent; add the client scope.
- **I8 — `cleartokens` command is bare.** `management/commands/cleartokens.py:6-9` ignores
  `CLEAR_EXPIRED_TOKENS_BATCH_SIZE`/`_INTERVAL`, emits no output, and lets exceptions escape as raw
  tracebacks. Add `--batch-size`/`--sleep`, summary output, and error handling.
- **I9 — `validate_refresh_token` mutates the request before the client-match check.**
  `oauth2_validators.py:833-838` sets `request.user`/`refresh_token_instance` before returning
  `rt.application == client`. Safe today (oauthlib aborts on `False`) but leaves
  attacker-influenced state on the request. Check ownership first.
- **I10 — `.first().token` can raise on the reuse path.** `oauth2_validators.py:708-710`. If the
  previous access token has no refresh token (revoked/deleted mid-flight), `.first()` is `None` and
  `.token` raises during a concurrent refresh. Guard for `None`.
- **I11 — `dotless_domain_re` accepts single-label hosts.** `validators.py:12-18`. Format-only
  (actual redirect enforcement is exact-match), but it lets admins register bare/internal hostnames.
  Confirm registration policy matches RFC 9700 §2.1.
- **I12 — `revoke_token` scans an unindexed column and can raise `MultipleObjectsReturned`.**
  `oauth2_validators.py:778-782`. The unique index is on `token_checksum`, not `token` (a
  `TextField`), so every revocation is a sequential scan; RefreshToken's `token` is not unique
  alone, so `.get(token=...)` can raise `MultipleObjectsReturned`, which is not caught. Look up
  AccessToken by `token_checksum` and handle multiplicity.
- **I13 — Basic-auth client-existence timing oracle.** `oauth2_validators.py:166-179`. For an
  unknown `client_id` the expensive `check_password` is skipped, so timing reveals whether a client
  exists. Minor (client_ids are not high-value secrets). Equalize with a dummy hash comparison.

---

## Verified sound (checked to avoid false positives)

These were examined and found correct — useful as a map of the library's existing defenses:

- **`prompt=none` open-redirect is already fixed.** `views/base.py:257-303` validates the
  authorization request (confirming the client + registered `redirect_uri`) **before** redirecting,
  so an unauthenticated `prompt=none` request cannot be turned into an open redirector. (This was a
  recent fix, commit `a11f11d`.)
- **CSRF exemptions are appropriate.** `TokenView`, `RevokeTokenView`, `IntrospectTokenView`, and
  `DeviceAuthorizationView` are client-authenticated, non-cookie endpoints (RFC 6749/7662/8628).
  The browser-facing `AuthorizationView` keeps CSRF protection.
- **Client-secret comparison is constant-time.** `_check_secret` (`oauth2_validators.py:120-130`)
  uses `check_password` for hashed secrets and `constant_time_compare` for legacy plaintext.
- **Token lookup by `token_checksum`** is an indexed hash of a high-entropy value; a byte-wise
  constant-time compare is unnecessary there.
- **Client id/secret generation uses a CSPRNG.** `generators.py` delegates to
  `oauthlib.common.generate_client_id`, which uses `random.SystemRandom`; length 40 (id) and 128
  (secret) give ample entropy. (Contrast H1, which is DOT's own `random`-based device code path.)
- **`save_bearer_token` is transactional.** Token persistence uses `transaction.atomic` with
  `select_for_update` locks (`oauth2_validators.py:611, 656, 673`), handling refresh concurrency.
- **JWT audience discovery re-verifies.** `_get_key_for_token` reads the unverified JWT only to
  find `aud`, then re-verifies with the resolved application key — no signature bypass observed.
- **No SQL injection.** All queries use the Django ORM with parameterized filters.
- **PKCE required by default** (`PKCE_REQUIRED=True`), **auth codes expire in 60s**, and
  **`allow_scopes` uses correct subset (fail-closed) semantics** (`models.py:448-460`).
- **`OAuth2ResponseRedirect.validate_redirect`** (`http.py:27-32`) rejects missing and disallowed
  schemes; `OAuth2Backend`/`OAuth2Authentication` convert oauthlib `ValueError` into
  `SuspiciousOperation` and otherwise fail closed.

---

## Suggested remediation order

1. **Quick, high-impact, low-risk:** H1 (`secrets.choice`), H2 (stop logging secrets), H3 (admin
   `list_display`/`search_fields`), L5 (`__str__`), L10 (`log.exception`). These are small,
   self-contained diffs that remove credential exposure.
2. **Correctness bug:** H5 (per-request scope list) — user-facing breakage waiting to happen.
3. **Spec-compliance with security weight:** M1 (revocation ownership), M4/M5 (redirect matching),
   M6/M7 (device flow throttle + owner-scoping), M2/M3 (introspection).
4. **Hardening defaults (may be a breaking change → major release):** M8, M10, I1 — token TTLs,
   refresh expiry/reuse protection, plaintext storage, https-only redirects.
5. **Correctness/interop:** H4 (HS256 key), L1/L2 (discovery), L4 (401 vs 403), L6/L7/L14
   (robustness), and the remaining informational items.
