# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- preserve the following to copy/paste on new releases -->
<!-- ## [unreleased] -->
<!-- ### Added -->
<!-- ### Changed -->
<!-- ### Deprecated -->
<!-- ### Removed -->
<!-- ### Fixed -->
<!-- ### Security -->

## [unreleased]
### Added
* #1762 RFC 7523 JWT client authentication (`private_key_jwt` / `client_secret_jwt`) at the token, introspection and
  revocation endpoints. Applications gain `token_endpoint_auth_method`, `client_jwks` and `client_jwks_uri` fields
  (deployments with a swapped/custom Application model must add an equivalent migration); remote JWK Sets are fetched
  with the same SSRF hardening as CIMD and cached. Includes a public `oauth2_provider.client_assertions.make_client_assertion()`
  helper for apps acting as OAuth clients, optional `private_key_jwt` authentication to a remote introspection endpoint
  (`RESOURCE_SERVER_INTROSPECTION_JWT_*` settings), Dynamic Client Registration support for both methods with
  `jwks`/`jwks_uri` metadata, and `*_auth_signing_alg_values_supported` advertisement in the discovery documents.
  Note that `client_secret_jwt` requires the client secret to be stored unhashed (it is the HMAC key), like HS256.
* #1816 A system check (`oauth2_provider.W012`) that warns when
  `REFRESH_TOKEN_REUSE_PROTECTION` is enabled while `ROTATE_REFRESH_TOKEN` is disabled.
  Replay is detected by recognizing a token a previous rotation superseded, so without
  rotation the protection never fires — a pairing `docs/settings.rst` already documented but
  nothing enforced.
* Support for OAuth 2.0 Pushed Authorization Requests (PAR, RFC 9126). A new `par/` endpoint
  (`PushedAuthorizationRequestView`) lets clients push authorization request parameters over an
  authenticated back channel in exchange for a single-use `request_uri`, stored on the swappable
  `PushedAuthorizationRequest` model. Enforcement can be required server-wide via
  `REQUIRE_PUSHED_AUTHORIZATION_REQUESTS` or per client via the application's
  `require_pushed_authorization_requests` field, and the endpoint is advertised in the RFC 8414
  metadata document. See `docs/pushed_authorization_requests.rst`.
* #1723 A new swappable `Authorization` model recording granted authorizations: the durable fact
  that a user — or a client acting on its own behalf — authorized a client for a set of scopes via
  a particular grant type. Every token-issuing flow records one (refreshing inherits the original
  rather than creating a new one), and access, refresh and ID tokens carry a nullable
  `authorization` foreign key tracing them back to it. The client is recorded durably as a
  `client_id` value, with the `Application` foreign key an optional `SET_NULL` pointer to the
  registration backing it, so deleting a registration does not destroy the record of the consent.
  Configurable via `OAUTH2_PROVIDER_AUTHORIZATION_MODEL` and `AUTHORIZATION_ADMIN_CLASS`; see
  `docs/authorizations.rst`. Deployments with swapped/custom token models must run
  `makemigrations` for the new foreign key.
* #1723 `Authorization.revoke()` revokes every token issued under an authorization, on every
  device, and closes the credentials that could still mint tokens under it (an unexchanged
  authorization code is deleted, an approved but unredeemed device grant is denied). Revocation,
  not deletion, is the domain action: the token foreign keys are `on_delete=RESTRICT`, and the
  admin exposes a "Revoke selected authorizations" action instead of add/change/delete.
### Changed
* #1723 An authorization code is no longer deleted when it is exchanged. The row is retained and
  stamped with a new `exchanged_at` timestamp, and `cleartokens` purges it once it expires.
  Retaining it makes a replay recognisable: a code presented after it was exchanged now revokes the
  tokens issued on the first exchange, per RFC 6749 §4.1.2 and RFC 9700 §4.5. Deployments that
  override `invalidate_authorization_code()` to delete the row keep working, but lose replay
  detection. `cleartokens` also purges revoked authorizations, but only once every token issued
  under them is gone.
* #1287 RP-Initiated Logout no longer rejects an `id_token_hint` whose ID Token is no longer stored.
  Such a request previously returned HTTP 400; it now takes the prompt-or-logout path, so deployments
  relying on the 400 will see 200 (prompt) or 302 (redirect) instead. "No longer stored" covers an ID
  Token deliberately revoked (`IDToken.revoke()` deletes the row) and one that never existed, not only
  one another RP's logout deleted. Verification itself is unchanged: a hint that cannot be verified is
  still rejected, and a `client_id` supplied alongside it is still required to match the RP the ID
  Token was issued for.
* #1287 Orphaned-`id_token_hint` requests that are still rejected now report the error they actually
  hit rather than a blanket invalid-ID-Token error, because the checks past that point are now
  reached. A mismatched `client_id` reports "Mismatch between the Client ID of the ID Token and the
  Client ID that was provided" and a `post_logout_redirect_uri` that is not the requesting RP's
  reports "Invalid post logout redirect URI", both still `invalid_request` with HTTP 400; declining
  the logout confirmation form now reports `logout_denied` rather than `invalid_request`. Deployments
  that branch on the `error` code or match on the description -- in a custom `error_response()`, an
  overridden `logout_confirm.html`, or log-based alerting -- should check those paths.
* #1287 `RPInitiatedLogoutView.validate_logout_request_user()` now returns an `(id_token, claims)`
  tuple rather than the `IDToken` alone, and `RPInitiatedLogoutView.get_request_application()` takes a
  third `claims` argument. Subclasses overriding either method must be updated.

### Fixed
* #1287 RP-Initiated Logout is now idempotent, as the specification requires. Once one RP logged an
  End-User out, `do_logout()` deleted that user's ID Tokens, so every other RP's `id_token_hint`
  referred to an IDToken that no longer existed and their logout requests failed with HTTP 400 and
  never reached their `post_logout_redirect_uri`. A verified hint whose IDToken is gone is now
  distinguished from one that could not be verified, and the requesting RP is recovered from the
  token's verified `aud` claim so that the `client_id` and `post_logout_redirect_uri` checks still
  apply.
* #1816 `RefreshToken.token_checksum` is now unique. `AbstractRefreshToken.Meta` declared
  `unique_together = ("token_checksum", "revoked")`, which enforced nothing: live rows have
  `revoked IS NULL` and every supported backend treats NULLs as distinct in a unique index,
  so any number of live refresh tokens could share one token value — while for revoked rows
  it only forbade two revoked at the identical microsecond. Since a refresh token value is
  the sole lookup key, duplicates left nothing to say which row a presented token meant.
  `revoked` leaves the key entirely, so the constraint is a plain unique index enforced
  identically on every backend, and the multi-row workarounds in `revoke_token` and
  `validate_refresh_token` collapse into single-row lookups.

  **Run `python manage.py migrate`.** Migration
  `0023_refreshtoken_unique_token_checksum` deletes refresh tokens that share a token value
  before applying the constraint, keeping the live row where there is one (so no active
  client is logged out) and otherwise the most recently created row. Deleting refresh
  tokens does not cascade into access tokens (`AccessToken.source_refresh_token` is
  `SET_NULL`). **Swapped refresh token models need their own migration:** the schema
  operations are skipped for a swapped model and the deduplication deliberately no-ops, so
  run `makemigrations` for your app and add an equivalent cleanup if your rows may contain
  duplicates.

  A duplicate can now only arise from a custom `REFRESH_TOKEN_GENERATOR` that returns an
  already-stored value; `_create_refresh_token` logs that and raises `InvalidGrantError`, so
  the token endpoint answers `400 invalid_grant` rather than raising a 500.

## [3.4.1] - 2026-08-21

This release is dominated by **security hardening of redirect URI matching, token revocation and
refresh token handling**. Several entries below change behavior that was previously accepted, and
they are spread across *Fixed* and *Security*: the **"Upgrading to 3.4.1"** section of the
Upgrading guide collects everything you need to act on in one place, so start there. Of particular
note: redirect URIs are now matched exactly per
[RFC 9700 §2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1), so a request may no
longer carry query parameters, path parameters, credentials or a fragment that the registered URI
does not have; `REFRESH_TOKEN_EXPIRE_SECONDS`, where set, is now enforced when a refresh token is
presented rather than only by the `cleartokens` sweep; and the built-in templates now link a
stylesheet shipped with the package instead of a CDN, so run `collectstatic` or the pages render
unstyled.

### Added
* #681 Redirect URI mismatches are now diagnosed on the `oauth2_provider` logger at `DEBUG`,
  reporting the requested URI, every registered candidate it was compared against, and which
  component of each one differed (scheme, hostname, port, path, query). The same detail is
  emitted for `post_logout_redirect_uri` and for the token endpoint's comparison against the
  URI recorded on the grant. The error response is unchanged: the registered URIs are never
  disclosed to the requester, only to the server's log. See "Debugging redirect URI
  mismatches" in the documentation. Note that `AbstractApplication.redirect_uri_allowed()`
  and `post_logout_redirect_uri_allowed()` now call the new `check_redirect_to_uri_allowed()`
  (same verdict, plus the mismatch reasons) instead of `redirect_to_uri_allowed()`, so code
  that wrapped or patched the latter to influence those methods must target the former.
* #634 A system check (`oauth2_provider.W011`) that warns when the `AccessToken` and
  `RefreshToken` models are swapped into different apps, and a new
  "Extending the token models" documentation section explaining how to swap the
  interrelated token models together.
* #1623 Documentation ("Content Security Policy and the authorization form") on completing
  the authorization-code flow under a strict `form-action` Content Security Policy, which
  Chromium enforces against the post-authorization redirect to the client's `redirect_uri`.
* #410 Documentation ("Resource scope syntax") clarifying that `TokenHasResourceScope`
  checks each `required_scopes` entry suffixed with the `READ_SCOPE`/`WRITE_SCOPE` setting
  value (defaults `read`/`write`, e.g. `music:read`, `music:write`), so a bare `music` scope
  is rejected; with the default settings-based scopes backend the suffixed scopes must be
  declared in `SCOPES`.
* #1157 An "Upgrading" documentation page collecting the breaking changes and upgrade steps for
  every release that needs them — 2.0, 3.0 and this release — linked from the documentation index,
  so upgrade guidance is discoverable outside the CHANGELOG. A release that asks nothing of you has
  no section there, so a gap between two versions is an answer rather than an omission.
* #452 Documentation ("Custom scopes backend") explaining how to replace the default
  settings-driven scopes backend via `SCOPES_BACKEND_CLASS`, including a worked model-based
  example that stores scopes in the database.
* #1045 Tutorial ("Managing applications and tokens in the Django admin") walking through the
  admin site for applications and issued tokens, including client-secret hashing, credential
  masking, and that tokens cannot be created by hand.
* #403 Translatable (`gettext_lazy`) `verbose_name` labels on every field of the
  `Application`, `Grant`, `AccessToken`, `RefreshToken`, `IDToken` and `DeviceGrant` models, so
  the Django admin and the authorization UI can be localized. Migration
  `oauth2_provider.0021_translatable_field_labels` records the label changes; it makes no
  database schema changes.
### Deprecated
* #1773 `JSONOAuthLibCore` (`OAUTH2_PROVIDER["OAUTH2_BACKEND_CLASS"]` set to
  `oauth2_provider.oauth2_backends.JSONOAuthLibCore`) is deprecated and now emits a
  `DeprecationWarning`. It makes the OAuth token, introspection, and
  revocation endpoints read `application/json` bodies, but those endpoints are defined to
  use `application/x-www-form-urlencoded` (RFC 6749, RFC 7662, RFC 7009); the JSON mode is
  non-standard and breaks interoperability with spec-compliant clients. It is scheduled for
  removal in 4.0.
### Changed
* #1343 `Application.clean()` now reports its validation errors per field instead of as
  non-field errors, and reports all of them at once instead of stopping at the first
  problem. The application forms (the built-in registration/edit views and the Django
  admin) render each message next to the offending input — a rejected redirect URI on
  `redirect_uris`, a non-https CORS origin on `allowed_origins`, an unusable algorithm on
  `algorithm`, and the HS256 client-secret conflicts on `client_secret` /
  `hash_client_secret`. `ValidationError.message_dict` is keyed by those field names, so
  callers of `Application.full_clean()` (including dynamic client registration and CIMD)
  now surface the field name alongside the message. A custom `ModelForm` that omits one of
  those fields still gets the message as a non-field error, provided it subclasses
  `oauth2_provider.forms.ApplicationForm`.
* #730 The templates shipped with the toolkit no longer load Bootstrap 2.3.2 from a
  third-party CDN. `oauth2_provider/base.html` now links a small stylesheet distributed
  with the package (`static/oauth2_provider/css/oauth2_provider.css`), which also absorbs
  the inline `<style>` block that template carried. The built-in pages therefore render in
  air-gapped installs and under a strict Content Security Policy such as
  `default-src 'self'`, which blocks a foreign style host and an inline style block alike,
  and the authorization page no longer makes an unpinned (no Subresource Integrity)
  third-party request while the user is making a consent decision. The stylesheet is served
  through `staticfiles`, so run `collectstatic` for the pages to be styled. The Bootstrap 2
  class names used by the templates are unchanged, and the `css` block of `base.html` is
  still the supported way to substitute your own styles.
* The `AccessToken` and `RefreshToken` admins now invalidate tokens through a **"Revoke selected"**
  action instead of raw delete (delete is disabled on those two admins). A raw delete of an access
  token left its bound refresh token behind (`RefreshToken.access_token` is `SET_NULL`) — an orphan
  that could still mint new access tokens — and a raw delete of a refresh token discarded the
  revoked tombstone that `REFRESH_TOKEN_REUSE_PROTECTION` relies on. The revoke action invalidates
  the whole token family consistently; expired rows are still pruned by `cleartokens`. `Grant` and
  `IDToken` admins keep the default delete. The access-token revoke logic is now a single shared
  `oauth2_provider.models.revoke_access_token()` helper used by the admin action, the `/revoke/`
  endpoint, and `AuthorizedTokenDeleteView`.
* #522 The `cleartokens` management command now prints a warning to stderr when
  `REFRESH_TOKEN_EXPIRE_SECONDS` is unset (or `0`), explaining that only revoked and
  orphaned refresh tokens are removed and that expired access/ID tokens still bound to a
  refresh token are retained until that refresh token is gone. The management-command docs
  were clarified to match.
* #746 Revoking an access token (via the RFC 7009 `/revoke/` endpoint) now also revokes
  the refresh token bound to it, matching the admin "delete access token" view and
  RFC 7009 §2.1. Previously the refresh token survived and could immediately mint a new
  access token, defeating the revocation and leaving the refresh token an active "orphan"
  (its `access_token` foreign key is `SET_NULL`). Whether a refresh token may survive
  access-token revocation will become a configurable policy in 4.0.
* #1715 Security guidance in the settings reference: recommend a finite
  `REFRESH_TOKEN_EXPIRE_SECONDS` as defense-in-depth (rotation remains the primary
  mitigation), and document why `OIDC_RP_INITIATED_LOGOUT_ACCEPT_EXPIRED_TOKENS` defaults
  to `True` (the `id_token_hint` is a previously issued token per OIDC RP-Initiated Logout)
  and how to harden it.
### Fixed
* The system check that verifies the `AccessToken`, `IDToken`, and `RefreshToken` models are
  routed to a single database is now registered under the `models` tag instead of `database`.
  Django 6.1 stopped running `database`-tagged checks unless a database alias is passed
  explicitly (`manage.py check --database default`), because such checks may do more than
  static analysis; this one only asks the configured routers where the token models would be
  written and never opens a connection, so under the old tag a plain `manage.py check` would
  have silently stopped reporting a cross-database token configuration on Django 6.1.
* #1809 `REFRESH_TOKEN_REUSE_PROTECTION` now revokes a compromised token family as a set
  instead of one row at a time. A rotating client keeps every refresh token it has ever been
  issued in the same family, so the old per-row loop cost one `SELECT ... FOR UPDATE` round
  trip per token in the family, paid again on every replay of the stale token: a client stuck
  on a retry timer could hold a worker and a database connection for tens of seconds per
  request. The sweep now runs in a fixed number of queries whatever the size of the family,
  through the new `AbstractRefreshToken.revoke_family()`, and `token_family` is indexed
  (migration `0022_refreshtoken_token_family_index`) so it no longer scans the whole refresh
  token table. What gets revoked is unchanged: every live member of the family, and the
  family's access tokens. If you swap in your own refresh token model, run `makemigrations` to
  pick up the index, and if you override `revoke()` override `revoke_family()` to match.
* #1796 Redirect URIs using an RFC 8252 §7.1 private-use URI scheme can now be registered.
  Such a scheme has no naming authority, so only a single slash follows it
  (`com.example.app:/oauth2redirect`), but `Application.clean()` reassembled every URI with
  `://` before validating and rejected the result with "Enter a valid URL." — leaving native
  apps no way to register the form the RFC prescribes and their clients actually send. The
  double-slash variant was not a workaround: the two spellings parse to different hostnames
  and produce `redirect_uri_mismatch` against each other. Schemes that require an authority
  (`http`, `https`, `ws`, `wss`, `ftp`) must still include a host, and the redundant
  `com.example.app:///oauth2redirect` and rootless `com.example.app:oauth2redirect` spellings
  are rejected so that each callback has one canonical registration (RFC 9700 §2.1).
  **Upgrade note:** the rootless spelling was previously accepted, but the same reassembly
  rewrote it to `com.example.app://oauth2redirect` — registering `oauth2redirect` as a
  *hostname*, which no client matches. It is now rejected at registration instead of being
  silently reinterpreted; re-register any such URI in the single-slash form.
* #1796 `redirect_to_uri_allowed()` no longer raises `AttributeError` when
  `ALLOW_URI_WILDCARDS` is enabled and a redirect URI has no hostname, as is the case for
  private-use URI scheme redirects.
* #746 `REFRESH_TOKEN_EXPIRE_SECONDS` is now enforced when a refresh token is presented,
  not only by the `cleartokens` (`clear_expired`) cleanup job. Previously a refresh token
  past its configured lifetime kept working until a cleanup sweep happened to remove it —
  or forever, if `cleartokens` was never scheduled. Expiry is idle-based: a refresh token
  is rejected `REFRESH_TOKEN_EXPIRE_SECONDS` after its access token expires (the deadline
  slides forward on every refresh), so actively-used tokens are unaffected. The default
  (`REFRESH_TOKEN_EXPIRE_SECONDS = None`) still never expires refresh tokens. **Upgrade
  note:** deployments that set `REFRESH_TOKEN_EXPIRE_SECONDS` may see idle refresh tokens
  that are already past their lifetime rejected on upgrade, forcing those clients to
  re-authenticate.
* #746 `clear_expired()` now reclaims "orphaned" refresh tokens — non-revoked refresh
  tokens whose access token was deleted out of band, leaving `access_token` `NULL`. The
  previous `access_token__expires__lt` join could never match a `NULL` access token, so
  such rows could remain in the database indefinitely.
* #1687 Reusing a refresh token within `REFRESH_TOKEN_GRACE_PERIOD_SECONDS` no longer
  raises `AttributeError: 'NoneType' object has no attribute 'token'` (HTTP 500) when the
  access token previously minted from that refresh token still exists but its own refresh
  token has since been removed — e.g. by `clear_expired` or a concurrent rotation.
  `_save_bearer_token` now re-issues a refresh token bound to the surviving access token
  instead of dereferencing the missing one (creating a fresh access token there would
  violate the one-to-one `AccessToken.source_refresh_token` relation).
* #958 Return a spec-compliant 400 instead of raising an uncaught `AssertionError`
  (HTTP 500) when an application without any registered `redirect_uris` (e.g. a
  `client_credentials` application) is driven through a flow that needs a default
  redirect URI. `Application.default_redirect_uri` now raises
  `oauthlib`'s `MissingRedirectURIError`, consistent with the multiple-URI case.
* #1260 `OAuth2Validator.validate_bearer_token` now rejects a token whose
  application is not usable (`Application.is_usable()` returns `False`) with an
  `invalid_token` error, mirroring the check the issuance path already performs
  in `_load_application`. The default `is_usable()` returns `True`, so this only
  affects swapped Application models that override it.
* #1169 The DRF `TokenHasScope` and `TokenMatchesOASRequirements` permissions now
  deny (return `False`) and log a warning, instead of raising an `AssertionError`
  (HTTP 500), when `request.auth` is not an OAuth2 access token. This lets them be
  composed with other permission classes (e.g. OR-ed) without a non-OAuth2 token
  turning into a server error.

### Security
* #1819 The device authorization flow's confirmation and status views now act only on a device
  grant that belongs to the signed-in user. `DeviceUserCodeView` claims a pending grant for the
  user who enters the `user_code`, but `DeviceConfirmView` and `DeviceGrantStatusView` looked the
  grant up by `client_id` and `user_code` alone. Any *other* authenticated user who learned that
  short, human-readable code — it is displayed on the device's screen for a person to read and
  type — could therefore approve the pending authorization, handing the device tokens bound to
  the account of the user who entered it, or deny it, or read its status page. RFC 8628 §3.3 has
  the user who is being asked to authorize the device grant that authorization. Both views now
  filter on `user=request.user` and return `404` to anyone else; a grant that has not yet been
  claimed through the user-code step likewise can no longer be confirmed by navigating straight
  to the confirmation URL.
* #1816 A refresh token that was **deliberately revoked** is no longer honored inside
  `REFRESH_TOKEN_GRACE_PERIOD_SECONDS`. The grace window exists to shield the token a
  client retries when it did not receive the rotated response, but `revoked` records both
  that supersession *and* a deliberate revocation (the RFC 7009 `/revoke/` endpoint,
  `AuthorizedTokenDeleteView`, the admin, RP-initiated logout, revoking the bound access
  token), and validation could not tell them apart. A revoked token was therefore usable
  for the length of the window, contrary to
  [RFC 7009 §2.1](https://datatracker.ietf.org/doc/html/rfc7009#section-2.1) ("the
  invalidation takes place immediately, and the token cannot be used again after the
  revocation"). With `ROTATE_REFRESH_TOKEN = False` it was additionally re-issued as a new
  live row carrying the same token value, bringing the repudiated credential back to life
  in the database. The two are now distinguished by whether the token was ever consumed to
  mint a successor access token. A genuine rotation retry inside the window is unaffected,
  and deployments on the default `REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 0` were never
  exposed.

  This generalizes a test that previously applied only when
  `REFRESH_TOKEN_REUSE_PROTECTION` was enabled, so it is also a behavior change with reuse
  protection off: a superseded token whose successor access token has since been deleted is
  now rejected inside the window rather than accepted.
* Redirect URIs are now matched exactly, as
  [RFC 9700 §2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1) requires
  ("authorization servers MUST utilize exact string matching except for port numbers in
  localhost redirection URIs of native apps") and OpenID Connect Core §3.1.2.1 restates
  via RFC 3986 §6.2.1 Simple String Comparison. Four deviations are closed, each of which
  let a request differ from the registered URI while still matching it:
  * A request could carry **query parameters that were never registered** — the check
    tested that the registered query was a *subset* of the requested one. An attacker
    could append parameters to an otherwise-legitimate `redirect_uri` and have the
    authorization server reflect them into the client's callback alongside the
    authorization code, the redirect-URI manipulation class described in
    [RFC 9700 §4.1](https://datatracker.ietf.org/doc/html/rfc9700#section-4.1).
  * A request could carry **path parameters** (`https://example.com/cb;evil=1`). `urlparse()`
    peels `;params` off the last path segment into a separate attribute, and only `.path`
    was compared, so these smuggled data to the callback the same way extra query
    parameters did. Matching now uses `urlsplit()`, which leaves them in the path.
  * A request could carry **credentials** (`https://evil@example.com/cb`). Only `.hostname`
    was compared, so userinfo rode along unnoticed. Credentials are not part of a
    registered callback and are now rejected on either side.
  * A request could carry a **fragment**, which `urlparse()` split off before comparison,
    so `https://example.com/cb#x` matched a registered `https://example.com/cb`.
    [RFC 6749 §3.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2) states
    the endpoint URI MUST NOT include a fragment component. A bare trailing `#` is an
    empty fragment component and is rejected too; a percent-encoded `%23` is not a
    fragment delimiter and is unaffected.

  Registration is tightened to match: `AllowedURIValidator` tested the *parsed* fragment,
  which is empty both for a URI with no fragment and for one ending in a bare `#`, so
  `https://example.com/cb#` was accepted at save time. With matching now denying any `#`,
  such a registration would be stored and then never authorize anything; it is rejected
  up front instead. Registering a URI ending in `#` now raises a `ValidationError` where
  it previously succeeded.

  Case-insensitive scheme/host comparison (RFC 3986 §6.2.2.1 normalization) and the
  RFC 8252 §7.3 loopback any-port exemption are unchanged; `ALLOW_URI_WILDCARDS` still
  opts out of exact host matching and remains flagged by `oauth2_provider.W009`/`E004`.

  **Upgrade note:** clients that pass per-request data through the `redirect_uri` query
  string will now be rejected — every query parameter must be registered, and in the same
  order. Register the full URI including its query, or move per-request data into the
  `state` parameter, which is what it is for. Applications whose registered
  `redirect_uris` already carry no query component are unaffected.
* #1510 Revoking an access token from the authorized-tokens page
  (`AuthorizedTokenDeleteView`) now also revokes the refresh token issued
  alongside it. Previously only the access token was deleted, leaving the
  refresh token usable to mint a fresh access token and defeating the
  revocation (a regression from 2.3.0). Per
  [RFC 7009 §2.1](https://datatracker.ietf.org/doc/html/rfc7009#section-2.1) an
  access token revocation may also revoke the respective refresh token; for a
  user-initiated revocation that is now the behavior.
* #1617 With `REFRESH_TOKEN_REUSE_PROTECTION` enabled, `REFRESH_TOKEN_GRACE_PERIOD_SECONDS`
  no longer extends the validity of a refresh token that is several generations old in
  the rotation chain. The grace period now only shields the *immediately preceding*
  refresh token (the token a client retries when it did not receive the rotated
  response); replaying an older, already-rotated-past token within the grace window is
  rejected and revokes the whole token family, instead of being honored (and, without a
  requested scope, minting a fresh token pair).
* #727 The token revocation endpoint (`/o/revoke_token/`) now only revokes tokens that
  were issued to the authenticated client. Previously it revoked any token matching the
  submitted value regardless of which application issued it, so a client could revoke
  another client's tokens. Per
  [RFC 7009 §2.1](https://datatracker.ietf.org/doc/html/rfc7009#section-2.1) the server
  verifies the token was issued to the client making the request; a token belonging to a
  different client is now left untouched and the endpoint still returns `200` (RFC 7009
  §2.2) without disclosing whether the token exists.
* #1799 RFC 7592 registration access tokens now honour `COMPLIANT_BCP_RFC9700_TOKEN_STORAGE`. The
  dynamic client registration views assigned the token straight onto the model instead of routing it
  through the storage path that honours the setting, so a deployment that had opted into hashed-at-rest
  storage still had this one token persisted in cleartext. The registration response and the management
  endpoint continue to return the token to its owner; only what is written to the database changes.

## [3.4.0] - 2026-07-23

The headline of this release is first-class support for the **Model Context Protocol (MCP)**
authorization server role.
MCP's authorization spec is built on a stack of modern OAuth RFCs,
and this cycle landed the whole stack: Authorization Server Metadata (RFC 8414) and Protected
Resource Metadata (RFC 9728) for discovery, Dynamic Client Registration (RFC 7591 / RFC 7592) and
OAuth Client ID Metadata Documents (CIMD) so clients can register themselves, Resource Indicators
(RFC 8707) for audience-bound access tokens, and the OAuth 2.0 Security Best Current Practice
(RFC 9700) together with the RFC 9207 `iss` parameter. The RFC 9700 compliance gates double as a
configurable **OAuth 2.1 security posture** — they can reject the implicit and password grants and
enforce S256-only PKCE (legacy behavior by default in 3.4, scheduled to flip to compliant in 4.0).
The new `ALLOW_LOCALHOST_LOOPBACK` setting smooths the ephemeral-port loopback callback used by
native clients such as Claude Code, MCP Inspector, and mcp-remote.

Beyond MCP, the release adds a **Django Ninja** integration alongside the existing DRF support and
support for RP-Initiated Registration, lifts the 255-character cap on refresh tokens (mirroring the
access-token checksum scheme), makes `cleartokens` reclaim revoked refresh tokens sooner, and
harmonizes Bearer `Authorization` header parsing across the middleware.

It also carries a **batch of security fixes**: an unauthenticated open redirect from the
authorization endpoint (`prompt=none`), HS256 ID tokens being signed with the *hashed* client
secret, cleartext tokens and codes exposed in the Django admin, client secrets written to debug
logs, and predictable device-flow `user_code` generation. Longstanding operational bugs are fixed
too, including a multi-database `migrate` deadlock (#1591) and duplicate unique indexes that broke
fresh installs on Oracle and strict MySQL (#1656).

**Before upgrading**, read the breaking-changes section below: most items are `makemigrations`
steps for swapped models, but applications using the `HS256` signing algorithm now require
`hash_client_secret=False`.

### WARNING - POTENTIAL BREAKING CHANGES
* Applications using the `HS256` signing algorithm must now be configured with
  `hash_client_secret=False`. Previously such applications signed ID tokens with the hashed client
  secret, producing tokens that relying parties could not verify. `Application.clean()` now raises a
  `ValidationError` for `HS256` + `hash_client_secret=True`, and `Application.jwk_key` raises
  `ImproperlyConfigured` at signing time if the secret is hashed. To migrate an affected
  application, recreate it (or reset its secret) with `hash_client_secret=False` so the plaintext
  secret is stored and can be used as the shared HMAC key.
* Changes to the `AbstractRefreshToken` model require doing a `manage.py migrate` after upgrading.
* If you use a swapped refresh token model (`OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL`) you will need to
  update your custom model with `manage.py makemigrations`. If your table already contains refresh
  tokens you must also backfill `token_checksum` with a data migration — adapt the batched backfill
  loop from `forwards_func` in
  `oauth2_provider/migrations/0015_refreshtoken_token_checksum.py` (dropping its swapped-model
  guard, the early return, and resolving your own model instead) and keep the same operation order:
  add nullable checksum → drop the old `("token", "revoked")` unique constraint → widen `token` to
  `TextField` → backfill → make checksum non-nullable → add the `("token_checksum", "revoked")`
  unique constraint.
* If you use a swapped application model (`OAUTH2_PROVIDER_APPLICATION_MODEL`), run
  `manage.py makemigrations` after upgrading: `AbstractApplication` gained a
  `registration_source` `CharField` (choices `manual`/`dcr`/`cimd`, default `manual`) to mark
  how an application was registered — for example via Dynamic Client Registration (#670). This
  replaces the never-released `dcr_created` `BooleanField`. Installs using the built-in Application
  model just need `manage.py migrate` (migration `0019`).
* If you use a swapped application model (`OAUTH2_PROVIDER_APPLICATION_MODEL`), run
  `manage.py makemigrations` after upgrading: for CIMD (#1742) `AbstractApplication` gained a
  nullable `cimd_expires_at` `DateTimeField`, and `client_id` widened from `max_length=100` to
  `255` so a metadata-document URL fits. Installs using the built-in Application model just need
  `manage.py migrate` (migration `0020`).
* If you use a swapped device grant model (`OAUTH2_PROVIDER_DEVICE_GRANT_MODEL`), run
  `manage.py makemigrations` after upgrading: the redundant field-level `unique=True` was removed
  from `AbstractDeviceGrant.device_code` (#1656), and `AbstractDeviceGrant.scope` changed from
  `CharField(max_length=64, null=True)` to a non-nullable `TextField(blank=True)` (#1693). When
  prompted for a default for existing NULL `scope` rows, provide the one-off default `""` —
  matching `oauth2_provider/migrations/0016_alter_devicegrant_scope.py`. Uniqueness remains enforced by the
  `<app_label>_<class>_unique_device_code` constraint. If you are doing a *fresh* install on
  Oracle (or a MySQL backend that raises warnings as errors), you must also regenerate — or
  hand-edit — your existing `CreateModel` migration for the swapped model, since it still declares
  both uniqueness rules and will fail the same way migration `0013` did.
* If you use a swapped access token model (`OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL`) and have **not
  yet applied** the `0012_add_token_checksum` migration (i.e. you are upgrading from a version
  below 3.0), its `token_checksum` backfill now deterministically skips the swapped model — the
  schema operations in that migration never applied to swapped models, and the old backfill only
  worked when the ordering of your app's migrations happened to allow it. `migrate` logs a warning
  when the backfill is skipped and your table contains access tokens. Until `token_checksum` is
  backfilled those tokens will not validate; no data is lost, and tokens work again as soon as the
  checksum is populated. To backfill, add a data migration to your app (ordered after your
  migration that adds `token_checksum`): adapt the batched backfill loop from `forwards_func` in
  `oauth2_provider/migrations/0012_add_token_checksum.py`, dropping its swapped-model guard (the
  early return) and resolving your own model instead. You can check for affected rows with
  `YourAccessToken.objects.filter(token_checksum__isnull=True).exists()`. Installs that already
  applied `0012` (any 3.x deployment) are unaffected.

### Added
* #1373 Integration and docs for Django Ninja authentication
* #1546 Support for RP-Initiated Registration
* #1099 Add RFC 8414 OAuth 2.0 Authorization Server Metadata endpoint (`/.well-known/oauth-authorization-server`)
* #1743 Add RFC 9728 OAuth 2.0 Protected Resource Metadata endpoint (`/.well-known/oauth-protected-resource`), plus opt-in
  mixins/decorators (`ProtectedResourceMetadataMixin`, `protected_resource_metadata`) and a DRF authenticator
  (`OAuth2ProtectedResourceAuthentication`) that advertise it via the `resource_metadata` `WWW-Authenticate` challenge parameter
* #1635 Dynamic help text on the application `client_secret` field, warning users to copy the
  secret on creation and explaining it is hashed and unrecoverable when editing. The help text is
  shared by both the Django admin application form and the front-end register/edit views: the
  `ApplicationAdmin` uses `ApplicationForm`, and a shared `oauth2_provider/js/application_form.js`
  updates the text live as the `hash_client_secret` checkbox is toggled on either surface. The
  form also warns immediately when the `HS256` algorithm is selected while the client secret is —
  or will be — hashed, instead of only surfacing the error on save. (#1697, #1740)
* #670 Dynamic Client Registration Protocol (RFC 7591 / RFC 7592) — `DynamicClientRegistrationView` and
  `DynamicClientRegistrationManagementView` with configurable permission classes and registration access
  tokens. Dynamically registered applications are flagged with `AbstractApplication.registration_source`
  set to `"dcr"` and can be filtered in the Django admin.
* #1739 `ALLOW_LOCALHOST_LOOPBACK` setting to extend the RFC 8252 §7.3 any-port loopback exemption to `http://localhost` redirect URIs (opt-in, default `False`)
* #1742 Support for OAuth Client ID Metadata Documents (CIMD,
  `draft-ietf-oauth-client-id-metadata-document`). A client may present an `https` URL as its
  `client_id`; when `CIMD_ENABLED` is on the server fetches, validates and persists the metadata
  document as a public application (SSRF-hardened fetch, failure backoff and an in-flight fetch cap).
  Applications resolved this way carry `AbstractApplication.registration_source` set to `"cimd"`.
  Registration can be gated with `CIMD_REGISTRATION_PERMISSION_CLASSES` (default allow-all;
  `HostAllowlistCIMDPermission` restricts it to `CIMD_ALLOWED_HOSTS`), and the
  `clearcimdapplications` management command prunes expired CIMD applications that hold no live
  tokens. See `docs/cimd.rst`.
* #1751 Advertise the Dynamic Client Registration endpoint as `registration_endpoint` in the RFC 8414
  authorization server metadata document when `DCR_ENABLED` is on
* #1626 RFC 8707 "Resource Indicators" support
  - clients can optionally specify `resource` parameter during authorization or access token requests
  - Resource binding stored in Grant, AccessToken and RefreshToken models
  - Token introspection endpoint returns `aud` claim for tokens with resource indicators
* #1749 [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) (OAuth 2.0 Security Best Current Practice) compliance
  gates, each controlled by a `COMPLIANT_BCP_RFC9700_<topic>` setting that defaults to `False` (current behavior,
  warns when the discouraged behavior is used) and is scheduled to default to `True` in 4.0 (enforces the
  compliant behavior): `COMPLIANT_BCP_RFC9700_IMPLICIT_GRANT` (§2.1.2),
  `COMPLIANT_BCP_RFC9700_PASSWORD_GRANT` (§2.4), `COMPLIANT_BCP_RFC9700_PKCE_METHOD` (§2.1.1),
  `COMPLIANT_BCP_RFC9700_ACCESS_TOKEN_TRANSPORT` (§4.3.2), `COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS` (§4.4),
  and `COMPLIANT_BCP_RFC9700_TOKEN_STORAGE` (§4). Enforced behaviors are also removed from the RFC 8414
  authorization-server metadata and the OIDC discovery document, so both stay consistent with what the
  server accepts.
* #1749 [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207) `iss` authorization-response parameter and the
  `authorization_response_iss_parameter_supported` metadata field (mix-up defense), gated by
  `COMPLIANT_BCP_RFC9700_AUTHZ_RESPONSE_ISS`.
* #1749 Config-validation gates for the RFC 9700 recommendations expressed through existing settings (the settings stay
  canonical; the gate only sets validation severity — insecure value → check Warning while the gate is `False`,
  check Error once it is `True`): `COMPLIANT_BCP_RFC9700_REFRESH_TOKEN`
  (`REFRESH_TOKEN_REUSE_PROTECTION`, §4.14.2), `COMPLIANT_BCP_RFC9700_REDIRECT_URI_SCHEME`
  (`ALLOWED_REDIRECT_URI_SCHEMES`, §2.1), `COMPLIANT_BCP_RFC9700_REDIRECT_URI_MATCHING`
  (`ALLOW_URI_WILDCARDS`, §4.1.1), and `COMPLIANT_BCP_RFC9700_PKCE_REQUIRED` (`PKCE_REQUIRED`, §2.1.1).
* #1749 A `--deploy` security system check that flags every RFC 9700 recommendation currently on a non-compliant value
  (warnings `oauth2_provider.W001`–`W010`, errors `oauth2_provider.E002`–`E005` when the corresponding
  config-validation gate is enabled), plus an error (`oauth2_provider.E001`) for the incompatible combination of
  hashed token storage and a non-zero `REFRESH_TOKEN_GRACE_PERIOD_SECONDS`.
* #1749 New `docs/security.rst` page mapping each RFC 9700 recommendation to the corresponding setting. The demo IdP
  exposes every gate as an `OAUTH2_PROVIDER_COMPLIANT_BCP_RFC9700_*` environment variable so the Docker image and the
  e2e suite can exercise both gate positions.
* #1660 Extract the `HttpRequest` creation in `OAuth2Validator.validate_user` into an overridable
  `build_http_request` method, so subclasses can pass extra attributes through to their authentication backends.

### Changed
* #1732 Bearer `Authorization` header parsing is now harmonized across the codebase via a shared
  `oauth2_provider.utils.parse_bearer_token` helper implementing RFC 7235 / RFC 6750 semantics.
  As a result, `OAuth2TokenMiddleware` and `OAuth2ExtraTokenMiddleware` now accept the scheme
  case-insensitively (e.g. a lowercase `bearer` header, which is RFC-correct, is no longer
  ignored) and no longer mis-parse non-Bearer schemes that merely start with `Bearer`
  (e.g. `BearerX token` was previously treated as a Bearer token and is now rejected).
* #1688 `cleartokens` now removes revoked refresh tokens once `REFRESH_TOKEN_GRACE_PERIOD_SECONDS`
  has passed, instead of keeping them until `REFRESH_TOKEN_EXPIRE_SECONDS`. When
  `REFRESH_TOKEN_REUSE_PROTECTION` is enabled, revoked tokens are still kept until they expire so
  that token reuse can be detected.
* #1601 `RefreshToken.token` is now a `TextField` and lookups use a new SHA-256 `token_checksum`
  field, removing the 255 character limit so long refresh tokens (e.g. Microsoft's JWT refresh
  tokens) are supported. This mirrors the `AccessToken.token_checksum` approach introduced in 3.0.0
  (#1447). The revocation endpoint also looks up access tokens by checksum now, restoring an indexed
  lookup there.
* #1652 The `0012_add_token_checksum` backfill now computes checksums in batched `bulk_update`
  calls (1000 rows per statement) instead of saving each access token individually, sharply
  reducing how long the migration locks the access token table on large installations. Running
  `cleartokens` before upgrading is still the best preparation for tables with many expired
  tokens. See the warning above if you use a swapped access token model.

### Deprecated
* #1749 Using the OAuth 2.0 implicit grant, the resource owner password credentials grant, the PKCE `plain`
  `code_challenge_method`, or an access token in the URI query string now emits a `DeprecationWarning`, per
  [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700). Each is gated by the corresponding
  `COMPLIANT_BCP_RFC9700_*` setting, whose default is scheduled to flip to `True` (enforcing rejection) in 4.0.
* #1700 Deprecate the `AUTHENTICATION_SERVER_EXP_TIME_ZONE` setting. Token introspection `exp` values are
  Unix timestamps and are always interpreted as UTC per RFC 7662/RFC 7519. The setting still works
  for backwards compatibility but now emits a `DeprecationWarning` and will be removed in a future
  release.

### Fixed
* #1619 Accept wildcard `redirect_uris` whose hostname uses the double-dash form required for
  Netlify deploy-preview URLs (`https://*--sitename.netlify.app`). The validator previously stripped
  only a single leading hyphen after removing the `*`, leaving a hostname that began with `-` and was
  rejected by `URIValidator`; it now strips up to two leading hyphens while rejecting longer runs.
* #694 `ReadWriteScopedResourceMixin.__new__()` no longer forwards positional/keyword arguments to
  `object.__new__()`, which raised `TypeError: object.__new__() takes exactly one argument` when
  instantiating any view mixing this in with any argument at all — notably breaking Django REST
  Framework's `cls(**initkwargs)` view instantiation.
* #1006 A `client_id` or `username` containing a NUL (`\x00`) byte no longer causes a 500 error
  on database backends (e.g. PostgreSQL) that raise `ValueError` instead of executing the query;
  such values are now correctly treated as not matching any client/user.
* #1738 Fix the `rw_protected_resource` decorator accumulating the read/write scope on a shared list
  across requests. The required-scope list was built once at decoration time and appended to on
  every request, so after a write (`POST`) request the `write` scope stayed in the list and a
  subsequent read (`GET`) request with a read-only token was wrongly rejected. The behaviour was
  request-order dependent, not thread-safe, and also mutated a caller-supplied `scopes` list. The
  read/write scope is now added to a fresh per-request list.
* #1693 `AbstractDeviceGrant.scope` is now a `TextField(blank=True)` like the other grant and token
  models, instead of `CharField(max_length=64, null=True)`. 64 characters is well below the limits
  common in the broader OAuth ecosystem (Okta allows 1024, Google 2048), so longer scope strings
  no longer fail or get truncated in the device authorization flow. Existing rows with a NULL
  scope are backfilled to an empty string by migration `0016`.
* #1593 Use `pk` instead of `id` in `clear_expired()` and `RefreshToken.revoke()` so token models with a custom primary key field are supported.
* #1594 Fix introspection token expiry handling to consistently use UTC and avoid the deprecated
  `datetime.utcfromtimestamp`.
* #1696 Fix `auth_time` in oauth2 validator when user has never logged in.
* #1603 Honor user-overridden `OIDC_SERVER_CLASS` when `OIDC_ENABLED` is `True` and `OAUTH2_SERVER_CLASS` is not explicitly set; previously only the default was used in this fallback path.
* #1591 Fix `migrate` hanging on `0012_add_token_checksum` when a database router or
  multi-database configuration is in use. The `RunPython` data migrations in `0006` and `0012` now
  pin their queries to `schema_editor.connection.alias`, so the backfill runs on the connection
  performing the migration instead of being routed to a second connection that deadlocks against
  the migration transaction's own locks. This also makes both migrations backfill the correct
  database when migrating a non-default alias (`migrate --database=...`). Thanks to Igor Petrik for
  the diagnosis and fix.
* #1656 Remove the redundant `unique=True` on `DeviceGrant.device_code`, which duplicated the
  `unique_device_code` `UniqueConstraint` and created two identical unique indexes on the same
  column. Fresh installs failed on Oracle (`ORA-02261`) and on MySQL backends that raise database
  warnings as errors (`ER_DUP_INDEX`, 1831). Migration `0013` is fixed in place because the
  duplicate was created inside `CREATE TABLE`, so a follow-up migration could never fix fresh
  installs. Databases that already applied the old `0013` keep one harmless extra unique index;
  it can optionally be dropped by hand. Thanks to Febin Micheal Antony (#1659) and
  moscowmule2240 (#1718) for the fixes.

### Security
* #1734 Generate device-flow `user_code` values with the cryptographically secure `secrets` module
  instead of the predictable `random` module (Mersenne Twister). The `user_code` is a device
  authorization credential and must be unguessable per
  [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) sections 5.1 and 5.2.
* #1735 Stop writing client secrets to the logs. On a failed client authentication, the `OAuth2Validator`
  logged the submitted `client_secret` (and, for Basic auth, the base64 `client_id:client_secret`
  credential string) at `DEBUG` level. These messages now log at most the `client_id` (when it is
  available; the base64/unicode decode-failure paths log a generic message with no credential), so
  password-equivalent client secrets and raw credential strings no longer leak into log files or
  aggregators.
* #1736 Stop exposing cleartext access tokens, refresh tokens, and authorization codes in the Django
  admin. The default `AccessTokenAdmin`, `RefreshTokenAdmin`, and `GrantAdmin` classes listed the
  raw `token`/`code` in `list_display` and included them in `search_fields`. Because these values
  are stored in cleartext, any staff user with view access saw replayable credentials, and
  searching placed them in the `?q=` query string (captured by access logs and browser history).
  The columns are now masked (last characters only) and are no longer searchable (search is
  available by application and user instead). The raw `token`/`code` field is also excluded from
  the admin change/view form, which showed the editable cleartext field to any staff user with view
  access; a masked read-only value is shown instead. Adding tokens/codes through the admin is now
  disabled (`has_add_permission` returns `False` on the `AccessToken`, `RefreshToken`, `Grant`, and
  `IDToken` admins) — these are issued by the OAuth flows and are not meant to be hand-created, and
  the add form would otherwise present an editable cleartext field. Relatedly, the `AccessToken`,
  `RefreshToken`, and `Grant` model `__str__` methods no longer return the raw token/code (which the
  admin renders in a row's change-page title and breadcrumbs, and which also appears in `repr()` and
  logs); they now return a `"<Model> #<pk>"` identifier.
* #1737 Fix HS256-signed ID tokens being signed with the *hashed* client secret. When an application
  used the `HS256` algorithm with `hash_client_secret=True` (the default), the ID token was signed
  with the stored password-hash string as the HMAC key instead of the shared client secret, so a
  relying party holding the real (plaintext) secret could never verify the signature — and a
  password hash was misused as a MAC key. `HS256` now requires `hash_client_secret=False`:
  `Application.clean()` rejects the combination, and `jwk_key` raises `ImproperlyConfigured`
  rather than emit an unverifiable token. `HS256` with an empty client secret is likewise rejected
  (an empty HMAC key would make ID tokens trivially forgeable). See the breaking-changes note above.
* #1719 Fix an unauthenticated open redirect from the authorization endpoint. A `prompt=none` request from
  an unauthenticated user was redirected to the supplied `redirect_uri` with a `login_required` error
  *before* the client and `redirect_uri` were validated, allowing an attacker to redirect a victim's
  browser to an arbitrary origin. The request is now validated against a registered client before any
  redirect, per [OpenID Connect Core 1.0 section 3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
  Reported by Brian Lee (SSLab, Georgia Tech).

## [3.3.0] - 2025-05-21

### Added
* #1637 Support for Django 6.0
* #1642 Provide App Name and Scope in Device Confirmation View

### Removed
* #1636 Remove support for Python 3.8 and 3.9

### Fixed
* #1628 Fix inaccurate help_text on client_secret field of Application model
* #1674 Add `list_select_related` to `RefreshTokenAdmin` to avoid unbounded `JOIN` queries on the changelist
* #1621 Fix device code tokens getting the wrong scope.
* #1683 Fix swapped `DeviceGrant` model usage across the device authorization flow
* #1689 Fix invalid `Cache-Control` header value on the OIDC JWKS endpoint
* #1692 Fix consent violation and scope escalation.

## [3.2.0] - 2025-11-13
### Added
* Support for Django 5.2
* Support for Python 3.14 (Django >= 5.2.8)
* #1539 Add device authorization grant support

### Fixed
* #1252 Fix crash  when 'client' is in token request body
* #1496 Fix error when Bearer token string is empty but preceded by `Bearer` keyword.
* #1630 use token_checksum for lookup in _get_token_from_authentication_server

## [3.1.0] - 2025-10-03
**NOTE**: This is the first release under the new [django-oauth](https://github.com/django-oauth) organization. The project moved in order to be more independent and to bypass quota limits on parallel CI jobs we were encountering in Jazzband. The project will emulate Django Commons going forward in it's operation. We're always on the lookout for willing maintainers and contributors. Feel free to start participating any time. PR's are always welcome.

### Added
* #1506 Support for Wildcard Origin and Redirect URIs - Adds a new setting [ALLOW_URL_WILDCARDS](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#allow-uri-wildcards). This feature is useful for working with CI service such as cloudflare, netlify, and vercel that offer branch
deployments for development previews and user acceptance testing.
* #1586 Turkish language support added

### Changed
The project is now hosted in the django-oauth organization.

### Fixed
* #1517 OP prompts for logout when no OP session
* #1512 client_secret not marked sensitive
* #1521 Fix 0012 migration loading access token table into memory
* #1584 Fix IDP container in docker compose environment could not find templates and static files.
* #1562 Fix: Handle AttributeError in IntrospectTokenView
* #1583 Fix: Missing pt_BR translations


## [3.0.1] - 2024-09-07
### Fixed
* #1491 Fix migration error when there are pre-existing Access Tokens.

## [3.0.0] - 2024-09-05

### WARNING - POTENTIAL BREAKING CHANGES
* Changes to the `AbstractAccessToken` model require doing a `manage.py migrate` after upgrading.
* If you use swappable models you will need to make sure your custom models are also updated (usually `manage.py makemigrations`).
* Old Django versions below 4.2 are no longer supported.
* A few deprecations warned about in 2.4.0 (#1345) have been removed. See below.

### Added
* #1366 Add Docker containerized apps for testing IDP and RP.
* #1454 Added compatibility with `LoginRequiredMiddleware` introduced in Django 5.1.

### Changed
* Many documentation and project internals improvements.
* #1446 Use generic models `pk` instead of `id`. This enables, for example, custom swapped models to have a different primary key field.
* #1447 Update token to TextField from CharField. Removing the 255 character limit enables supporting JWT tokens with additional claims.
  This adds a SHA-256 `token_checksum` field that is used to validate tokens.
* #1450 Transactions wrapping writes of the Tokens now rely on Django's database routers to determine the correct
  database to use instead of assuming that 'default' is the correct one.
* #1455 Changed minimum supported Django version to >=4.2.

### Removed
* #1425 Remove deprecated `RedirectURIValidator`, `WildcardSet` per #1345; `validate_logout_request` per #1274

### Fixed
* #1444, #1476 Fix several 500 errors to instead raise appropriate errors.
* #1469 Fix `ui_locales` request parameter triggers `AttributeError` under certain circumstances

### Security
* #1452 Add a new setting [`REFRESH_TOKEN_REUSE_PROTECTION`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#refresh-token-reuse-protection).
  In combination with [`ROTATE_REFRESH_TOKEN`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#rotate-refresh-token),
  this prevents refresh tokens from being used more than once. See more at
  [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-29#name-recommendations)
* #1481 Bump oauthlib version required to 3.2.2 and above to address [CVE-2022-36087](https://github.com/advisories/GHSA-3pgj-pg6c-r5p7).

## [2.4.0] - 2024-05-13

### WARNING
Issues caused by **Release 2.0.0 breaking changes** continue to be logged. Please **make sure to carefully read these release notes** before
performing a MAJOR upgrade to 2.x.

These issues both result in `{"error": "invalid_client"}`:

1. The application client secret is now hashed upon save. You must copy it before it is saved. Using the hashed value will fail.

2. `PKCE_REQUIRED` is now `True` by default. You should use PKCE with your client or set `PKCE_REQUIRED=False` if you are unable to fix the client.

If you are going to revert migration 0006 make note that previously hashed client_secret cannot be reverted!

### Added
* #1304 Add `OAuth2ExtraTokenMiddleware` for adding access token to request.
  See [Setup a provider](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial_03.html#setup-a-provider) in the Tutorial.
* #1273 Performance improvement: Add caching of loading of OIDC private key.
* #1285 Add `post_logout_redirect_uris` field in the [Application Registration form](https://django-oauth-toolkit.readthedocs.io/en/latest/templates.html#application-registration-form-html)
* #1311,#1334 (**Security**) Add option to disable client_secret hashing to allow verifying JWTs' signatures when using
  [HS256 keys](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#using-hs256-keys).
  This means your client secret will be stored in cleartext but is the only way to successfully use HS256 signed JWT's.
* #1350 Support Python 3.12 and Django 5.0
* #1367 Add `code_challenge_methods_supported` property to auto discovery information, per [RFC 8414 section 2](https://www.rfc-editor.org/rfc/rfc8414.html#page-7)
* #1328 Adds the ability to [define how to store a user profile](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#define-where-to-store-the-profile).

### Fixed
* #1292 Interpret `EXP` in AccessToken always as UTC instead of (possibly) local timezone.
  Use setting `AUTHENTICATION_SERVER_EXP_TIME_ZONE` to enable different time zone in case the remote
  authentication server does not provide EXP in UTC.
* #1323 Fix instructions in [documentation](https://django-oauth-toolkit.readthedocs.io/en/latest/getting_started.html#authorization-code)
  on how to create a code challenge and code verifier
* #1284 Fix a 500 error when trying to logout with no id_token_hint even if the browser session already expired.
* #1296 Added reverse function in migration `0006_alter_application_client_secret`. Note that reversing this migration cannot undo a hashed `client_secret`.
* #1345 Fix encapsulation for Redirect URI scheme validation. Deprecates `RedirectURIValidator` in favor of `AllowedURIValidator`.
* #1357 Move import of setting_changed signal from test to django core modules.
* #1361 Fix prompt=none redirects to login screen
* #1380 Fix AttributeError in OAuth2ExtraTokenMiddleware when a custom AccessToken model is used.
* #1288 Fix #1276 which attempted to resolve #1092 for requests that don't have a client_secret per [RFC 6749 4.1.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1)
* #1337 Gracefully handle expired or deleted refresh tokens, in `validate_user`.
* Various documentation improvements: #1410, #1408, #1405, #1399, #1401, #1396, #1375, #1162, #1315, #1307

### Removed
* #1350 Remove support for Python 3.7 and Django 2.2

## [2.3.0] 2023-05-31

### WARNING

Issues caused by **Release 2.0.0 breaking changes** continue to be logged. Please **make sure to carefully read these release notes** before
performing a MAJOR upgrade to 2.x.

These issues both result in `{"error": "invalid_client"}`:

1. The application client secret is now hashed upon save. You must copy it before it is saved. Using the hashed value will fail.

2. `PKCE_REQUIRED` is now `True` by default. You should use PKCE with your client or set `PKCE_REQUIRED=False` if you are unable to fix the client.

### Added
* Add Japanese(日本語) Language Support
* #1244 implement [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
* #1092 Allow Authorization Code flow without a client_secret per [RFC 6749 2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1)
* #1264 Support Django 4.2.

### Changed
* #1222 Remove expired ID tokens alongside access tokens in `cleartokens` management command
* #1267, #1253, #1251, #1250, #1224, #1212, #1211 Various documentation improvements

## [2.2.0] 2022-10-18

### Added
* #1208 Add 'code_challenge_method' parameter to authorization call in documentation
* #1182 Add 'code_verifier' parameter to token requests in documentation

### Changed
* #1203 Support Django 4.1.

### Fixed
* #1203 Remove upper version bound on Django, to allow upgrading to Django 4.1.1 bugfix release.
* #1210 Handle oauthlib errors on create token requests

## [2.1.0] 2022-06-19

### Added
* #1164 Support `prompt=login` for the OIDC Authorization Code Flow end user [Authentication Request](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
* #1163 Add French (fr) translations.
* #1166 Add Spanish (es) translations.

### Changed
* #1152 `createapplication` management command enhanced to display an auto-generated secret before it gets hashed.
* #1172, #1159, #1158 documentation improvements.

### Fixed
* #1147 Fixed 2.0.0 implementation of [hashed](https://docs.djangoproject.com/en/stable/topics/auth/passwords/) client secret to work with swapped models.

## [2.0.0] 2022-04-24

This is a major release with **BREAKING** changes. Please make sure to review these changes before upgrading:

### Added
* #1106 OIDC: Add "scopes_supported" to the [ConnectDiscoveryInfoView](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#connectdiscoveryinfoview).
  This completes the view to provide all the REQUIRED and RECOMMENDED [OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
* #1128 Documentation: [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial_05.html)
  on using Celery to automate clearing expired tokens.

### Changed
* #1129 (**Breaking**) Changed default value of PKCE_REQUIRED to True. This is a **breaking change**. Clients without
  PKCE enabled will fail to authenticate. This breaks with [section 5 of RFC7636](https://datatracker.ietf.org/doc/html/rfc7636)
  in favor of the [OAuth2 Security Best Practices for Authorization Code Grants](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1).
  If you want to retain the pre-2.x behavior, set `PKCE_REQUIRED = False` in your settings.py
* #1093 (**Breaking**) Changed to implement [hashed](https://docs.djangoproject.com/en/stable/topics/auth/passwords/)
  client_secret values. This is a **breaking change** that will migrate all your existing
  cleartext `application.client_secret` values to be hashed with Django's default password hashing algorithm
  and can not be reversed. When adding or modifying an Application in the Admin console, you must copy the
  auto-generated or manually-entered `client_secret` before hitting Save.
* #1108 OIDC: (**Breaking**) Add default configurable OIDC standard scopes that determine which claims are returned.
  If you've [customized OIDC responses](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#customizing-the-oidc-responses)
  and want to retain the pre-2.x behavior, set `oidc_claim_scope = None` in your subclass of `OAuth2Validator`.
* #1108 OIDC: Make the `access_token` available to `get_oidc_claims` when called from `get_userinfo_claims`.
* #1132: Added `--algorithm` argument to `createapplication` management command

### Fixed
* #1108 OIDC: Fix `validate_bearer_token()` to properly set `request.scopes` to the list of granted scopes.
* #1132: Fixed help text for `--skip-authorization` argument of the `createapplication` management command.

### Removed
* #1124 (**Breaking**, **Security**) Removes support for insecure `urn:ietf:wg:oauth:2.0:oob` and `urn:ietf:wg:oauth:2.0:oob:auto` which are replaced
  by [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) "OAuth 2.0 for Native Apps" BCP. Google has
  [deprecated use of oob](https://developers.googleblog.com/2022/02/making-oauth-flows-safer.html?m=1#disallowed-oob) with
  a final end date of 2022-10-03. If you still rely on oob support in django-oauth-toolkit, do not upgrade to this release.

## [1.7.1] 2022-03-19

### Removed
* #1126 Reverts #1070 which incorrectly added Celery auto-discovery tasks.py (as described in #1123) and because it conflicts
  with Huey's auto-discovery which also uses tasks.py as described in #1114. If you are using Celery or Huey, you'll need
  to separately implement these tasks.

## [1.7.0] 2022-01-23

### Added
* #969 Add batching of expired token deletions in `cleartokens` management command and `models.clear_expired()`
  to improve performance for removal of large numbers of expired tokens. Configure with
  [`CLEAR_EXPIRED_TOKENS_BATCH_SIZE`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#clear-expired-tokens-batch-size) and
  [`CLEAR_EXPIRED_TOKENS_BATCH_INTERVAL`](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#clear-expired-tokens-batch-interval).
* #1070 Add a Celery task for clearing expired tokens, e.g. to be scheduled as a [periodic task](https://docs.celeryproject.org/en/stable/userguide/periodic-tasks.html).
* #1062 Add Brazilian Portuguese (pt-BR) translations.
* #1069 OIDC: Add an alternate form of
  [get_additional_claims()](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-claims-to-the-id-token)
  which makes the list of additional `claims_supported` available at the OIDC auto-discovery endpoint (`.well-known/openid-configuration`).

### Fixed
* #1012 Return 200 status code with `{"active": false}` when introspecting a nonexistent token
  per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2). It had been incorrectly returning 401.

## [1.6.3] 2022-01-11

### Fixed
* #1085 Fix for #1083 admin UI search for idtoken results in `django.core.exceptions.FieldError: Cannot resolve keyword 'token' into field.`

### Added
* #1085 Add admin UI search fields for additional models.

## [1.6.2] 2022-01-06

**NOTE: This release reverts an inadvertently-added breaking change.**

### Fixed

* #1056 Add missing migration triggered by [Django 4.0 changes to the migrations autodetector](https://docs.djangoproject.com/en/4.0/releases/4.0/#migrations-autodetector-changes).
* #1068 Revert #967 which incorrectly changed an API. See #1066.

## [1.6.1] 2021-12-23

### Changed
* Note: Only Django 4.0.1+ is supported due to a regression in Django 4.0.0. [Explanation](https://github.com/django-oauth/django-oauth-toolkit/pull/1046#issuecomment-998015272)

### Fixed
* Miscellaneous 1.6.0 packaging issues.

## [1.6.0] 2021-12-19
### Added
* #949 Provide django.contrib.auth.authenticate() with a `request` for compatibility with more backends (like django-axes).
* #968, #1039 Add support for Django 3.2 and 4.0.
* #953 Allow loopback redirect URIs using random ports as described in [RFC8252 section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3).
* #972 Add Farsi/fa language support.
* #978 OIDC: Add support for [rotating multiple RSA private keys](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#rotating-the-rsa-private-key).
* #978 OIDC: Add new [OIDC_JWKS_MAX_AGE_SECONDS](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#oidc-jwks-max-age-seconds) to improve `jwks_uri` caching.
* #967 OIDC: Add [additional claims](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-claims-to-the-id-token) beyond `sub` to the id_token.
* #1041 Add a search field to the Admin UI (e.g. for search for tokens by email address).

### Changed
* #981 Require redirect_uri if multiple URIs are registered per [RFC6749 section 3.1.2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3)
* #991 Update documentation of [REFRESH_TOKEN_EXPIRE_SECONDS](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html#refresh-token-expire-seconds) to indicate it may be `int` or `datetime.timedelta`.
* #977 Update [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/stable/tutorial/tutorial_01.html#) to show required `include`.

### Removed
* #968 Remove support for Django 3.0 & 3.1 and Python 3.6
* #1035 Removes default_app_config for Django Deprecation Warning
* #1023 six should be dropped

### Fixed
* #963 Fix handling invalid hex values in client query strings with a 400 error rather than 500.
* #973 [Tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial_01.html#start-your-app) updated to use `django-cors-headers`.
* #956 OIDC: Update documentation of [get_userinfo_claims](https://django-oauth-toolkit.readthedocs.io/en/latest/oidc.html#adding-information-to-the-userinfo-service) to add the missing argument.


## [1.5.0] 2021-03-18

### Added
* #915 Add optional OpenID Connect support.

### Changed
* #942 Help via defunct Google group replaced with using GitHub issues

## [1.4.1] 2021-03-12

### Changed
* #925 OAuth2TokenMiddleware converted to new style middleware, and no longer extends MiddlewareMixin.

### Removed
* #936 Remove support for Python 3.5

## [1.4.0] 2021-02-08

### Added
* #917 Documentation improvement for Access Token expiration.
* #916 (for DOT contributors) Added `tox -e livedocs` which launches a local web server on `localhost:8000`
  to display Sphinx documentation with live updates as you edit.
* #891 (for DOT contributors) Added [details](https://django-oauth-toolkit.readthedocs.io/en/latest/contributing.html)
  on how best to contribute to this project.
* #884 Added support for Python 3.9
* #898 Added the ability to customize classes for django admin
* #690 Added pt-PT translations to HTML templates. This enables adding additional translations.

### Fixed
* #906 Made token revocation not apply a limit to the `select_for_update` statement (impacts Oracle 12c database).
* #903 Disable `redirect_uri` field length limit for `AbstractGrant`

## [1.3.3] 2020-10-16

### Added
* added `select_related` in intospect view for better query performance
* #831 Authorization token creation now can receive an expire date
* #831 Added a method to override Grant creation
* #825 Bump oauthlib to 3.1.0 to introduce PKCE
* Support for Django 3.1

### Fixed
* #847: Fix inappropriate message when response from authentication server is not OK.

### Changed
* few smaller improvements to remove older django version compatibility #830, #861, #862, #863

## [1.3.2] 2020-03-24

### Fixed
* Fixes: 1.3.1 inadvertently uploaded to pypi with an extra migration (0003...) from a dev branch.

## [1.3.1] 2020-03-23

### Added
* #725: HTTP Basic Auth support for introspection (Fix issue #709)

### Fixed
* #812: Reverts #643 pass wrong request object to authenticate function.
* Fix concurrency issue with refresh token requests (#[810](https://github.com/django-oauth/django-oauth-toolkit/pull/810))
* #817: Reverts #734 tutorial documentation error.


## [1.3.0] 2020-03-02

### Added
* Add support for Python 3.7 & 3.8
* Add support for Django>=2.1,<3.1
* Add requirement for oauthlib>=3.0.1
* Add support for [Proof Key for Code Exchange (PKCE, RFC 7636)](https://tools.ietf.org/html/rfc7636).
* Add support for custom token generators (e.g. to create JWT tokens).
* Add new `OAUTH2_PROVIDER` [settings](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html):
  - `ACCESS_TOKEN_GENERATOR` to override the default access token generator.
  - `REFRESH_TOKEN_GENERATOR` to override the default refresh token generator.
  - `EXTRA_SERVER_KWARGS` options dictionary for oauthlib's Server class.
  - `PKCE_REQUIRED` to require PKCE.
* Add `createapplication` management command to create an application.
* Add `id` in toolkit admin console applications list.
* Add nonstandard Google support for [urn:ietf:wg:oauth:2.0:oob] `redirect_uri`
  for [Google OAuth2](https://developers.google.com/identity/protocols/OAuth2InstalledApp) "manual copy/paste".
  **N.B.** this feature appears to be deprecated and replaced with methods described in
  [RFC 8252: OAuth2 for Native Apps](https://tools.ietf.org/html/rfc8252) and *may* be deprecated and/or removed
  from a future release of Django-oauth-toolkit.

### Changed
* Change this change log to use [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
* **Backwards-incompatible** squashed migrations:
  If you are currently on a release < 1.2.0, you will need to first install 1.2.0 then `manage.py migrate` before
  upgrading to >= 1.3.0.
* Improved the [tutorial](https://django-oauth-toolkit.readthedocs.io/en/latest/tutorial/tutorial.html).

### Removed
* Remove support for Python 3.4
* Remove support for Django<=2.0
* Remove requirement for oauthlib<3.0

### Fixed
* Fix a race condition in creation of AccessToken with external oauth2 server.
* Fix several concurrency issues. (#[638](https://github.com/django-oauth/django-oauth-toolkit/issues/638))
* Fix to pass `request` to `django.contrib.auth.authenticate()` (#[636](https://github.com/django-oauth/django-oauth-toolkit/issues/636))
* Fix missing `oauth2_error` property exception oauthlib_core.verify_request method raises exceptions in authenticate.
  (#[633](https://github.com/django-oauth/django-oauth-toolkit/issues/633))
* Fix "django.db.utils.NotSupportedError: FOR UPDATE cannot be applied to the nullable side of an outer join" for postgresql.
  (#[714](https://github.com/django-oauth/django-oauth-toolkit/issues/714))
* Fix to return a new refresh token during grace period rather than the recently-revoked one.
  (#[702](https://github.com/django-oauth/django-oauth-toolkit/issues/702))
* Fix a bug in refresh token revocation.
  (#[625](https://github.com/django-oauth/django-oauth-toolkit/issues/625))

## 1.2.0 [2018-06-03]

* **Compatibility**: Python 3.4 is the new minimum required version.
* **Compatibility**: Django 2.0 is the new minimum required version.
* **New feature**: Added TokenMatchesOASRequirements Permissions.
* validators.URIValidator has been updated to match URLValidator behaviour more closely.
* Moved `redirect_uris` validation to the application clean() method.


## 1.1.2 [2018-05-12]

* Return state with Authorization Denied error (RFC6749 section 4.1.2.1)
* Fix a crash with malformed base64 authentication headers
* Fix a crash with malformed IPv6 redirect URIs

## 1.1.1 [2018-05-08]

* **Critical**: Django OAuth Toolkit 1.1.0 contained a migration that would revoke all existing
  RefreshTokens (`0006_auto_20171214_2232`). This release corrects the migration.
  If you have already ran it in production, please see the following issue for more details:
  https://github.com/django-oauth/django-oauth-toolkit/issues/589


## 1.1.0 [2018-04-13]

* **Notice**: The Django OAuth Toolkit project is now hosted by JazzBand.
* **Compatibility**: Django 1.11 is the new minimum required version. Django 1.10 is no longer supported.
* **Compatibility**: This will be the last release to support Django 1.11 and Python 2.7.
* **New feature**: Option for RFC 7662 external AS that uses HTTP Basic Auth.
* **New feature**: Individual applications may now override the `ALLOWED_REDIRECT_URI_SCHEMES`
  setting by returning a list of allowed redirect uri schemes in `Application.get_allowed_schemes()`.
* **New feature**: The new setting `ERROR_RESPONSE_WITH_SCOPES` can now be set to True to include required
  scopes when DRF authorization fails due to improper scopes.
* **New feature**: The new setting `REFRESH_TOKEN_GRACE_PERIOD_SECONDS` controls a grace period during which
  refresh tokens may be reused.
* An `app_authorized` signal is fired when a token is generated.

## 1.0.0 [2017-06-07]

* **New feature**: AccessToken, RefreshToken and Grant models are now swappable.
* #477: **New feature**: Add support for RFC 7662 (IntrospectTokenView, introspect scope)
* **Compatibility**: Django 1.10 is the new minimum required version
* **Compatibility**: Django 1.11 is now supported
* **Backwards-incompatible**: The `oauth2_provider.ext.rest_framework` module
  has been moved to `oauth2_provider.contrib.rest_framework`
* #177: Changed `id` field on Application, AccessToken, RefreshToken and Grant to BigAutoField (bigint/bigserial)
* #321: Added `created` and `updated` auto fields to Application, AccessToken, RefreshToken and Grant
* #476: Disallow empty redirect URIs
* Fixed bad `url` parameter in some error responses.
* Django 2.0 compatibility fixes.
* The dependency on django-braces has been dropped.
* The oauthlib dependency is no longer pinned.

## 0.12.0 [2017-02-24]

* **New feature**: Class-based scopes backends. Listing scopes, available scopes and default scopes
  is now done through the class that the `SCOPES_BACKEND_CLASS` setting points to.
  By default, this is set to `oauth2_provider.scopes.SettingsScopes` which implements the
  legacy settings-based scope behaviour. No changes are necessary.
* **Dropped support for Python 3.2 and Python 3.3**, added support for Python 3.6
* Support for the `scopes` query parameter, deprecated in 0.6.1, has been dropped
* #448: Added support for customizing applications' allowed grant types
* #141: The `is_usable(request)` method on the Application model can be overridden to dynamically
  enable or disable applications.
* #434: Relax URL patterns to allow for UUID primary keys


## 0.11.0 [2016-12-1]

* #315: AuthorizationView does not overwrite requests on get
* #425: Added support for Django 1.10
* #396: added an IsAuthenticatedOrTokenHasScope Permission
* #357: Support multiple-user clients by allowing User to be NULL for Applications
* #389: Reuse refresh tokens if enabled.


## 0.10.0 [2015-12-14]

* **#322: dropping support for python 2.6 and django 1.4, 1.5, 1.6**
* #310: Fixed error that could occur sometimes when checking validity of incomplete AccessToken/Grant
* #333: Added possibility to specify the default list of scopes returned when scope parameter is missing
* #325: Added management views of issued tokens
* #249: Added a command to clean expired tokens
* #323: Application registration view uses custom application model in form class
* #299: `server_class` is now pluggable through Django settings
* #309: Add the py35-django19 env to travis
* #308: Use compact syntax for tox envs
* #306: Django 1.9 compatibility
* #288: Put additional information when generating token responses
* #297: Fixed doc about SessionAuthenticationMiddleware
* #273: Generic read write scope by resource


## 0.9.0 [2015-07-28]

* ``oauthlib_backend_class`` is now pluggable through Django settings
* #127: ``application/json`` Content-Type is now supported using ``JSONOAuthLibCore``
* #238: Fixed redirect uri handling in case of error
* #229: Invalidate access tokens when getting a new refresh token
* added support for oauthlib 1.0


## 0.8.2 [2015-06-25]

* Fix the migrations to be two-step and allow upgrade from 0.7.2

## 0.8.1 [2015-04-27]

* South migrations fixed. Added new django migrations.

## 0.8.0 [2015-03-27]

* Several docs improvements and minor fixes
* #185: fixed vulnerabilities on Basic authentication
* #173: ProtectResourceMixin now allows OPTIONS requests
* Fixed `client_id` and `client_secret` characters set
* #169: hide sensitive information in error emails
* #161: extend search to all token types when revoking a token
* #160: return empty response on successful token revocation
* #157: skip authorization form with ``skip_authorization_completely`` class field
* #155: allow custom uri schemes
* fixed ``get_application_model`` on Django 1.7
* fixed non rotating refresh tokens
* #137: fixed base template
* customized ``client_secret`` length
* #38: create access tokens not bound to a user instance for *client credentials* flow


## 0.7.2 [2014-07-02]

* Don't pin oauthlib

## 0.7.1 [2014-04-27]

* Added database indexes to the OAuth2 related models to improve performances.

**Warning: schema migration does not work for sqlite3 database, migration should be performed manually**

## 0.7.0 [2014-03-01]

* Created a setting for the default value for approval prompt.
* Improved docs
* Don't pin django-braces and six versions

**Backwards incompatible changes in 0.7.0**

* Make Application model truly "swappable" (introduces a new non-namespaced setting `OAUTH2_PROVIDER_APPLICATION_MODEL`)


## 0.6.1 [2014-02-05]

* added support for `scope` query parameter keeping backwards compatibility for the original `scopes` parameter.
* __str__ method in Application model returns content of `name` field when available

## 0.6.0 [2014-01-26]

* oauthlib 0.6.1 support
* Django dev branch support
* Python 2.6 support
* Skip authorization form via `approval_prompt` parameter

**Bugfixes**

* Several fixes to the docs
* Issue #71: Fix migrations
* Issue #65: Use OAuth2 password grant with multiple devices
* Issue #84: Add information about login template to tutorial.
* Issue #64: Fix urlencode clientid secret


## 0.5.0 [2013-09-17]

* oauthlib 0.6.0 support

**Backwards incompatible changes in 0.5.0**

* `backends.py` module has been renamed to `oauth2_backends.py` so you should change your imports whether
  you're extending this module

**Bugfixes**

* Issue #54: Auth backend proposal to address #50
* Issue #61: Fix contributing page
* Issue #55: Add support for authenticating confidential client with request body params
* Issue #53: Quote characters in the url query that are safe for Django but not for oauthlib


## 0.4.1 [2013-09-06]

* Optimize queries on access token validation

## 0.4.0 [2013-08-09]

**New Features**

* Add Application management views, you no more need the admin to register, update and delete your application.
* Add support to configurable application model
* Add support for function based views

**Backwards incompatible changes in 0.4.0**

* `SCOPE` attribute in settings is now a dictionary to store `{'scope_name': 'scope_description'}`
* Namespace `oauth2_provider` is mandatory in urls. See issue #36

**Bugfixes**

* Issue #25: Bug in the Basic Auth parsing in Oauth2RequestValidator
* Issue #24: Avoid generation of `client_id` with ":" colon char when using HTTP Basic Auth
* Issue #21: IndexError when trying to authorize an application
* Issue #9: `default_redirect_uri` is mandatory when `grant_type` is implicit, `authorization_code` or all-in-one
* Issue #22: Scopes need a verbose description
* Issue #33: Add django-oauth-toolkit version on example main page
* Issue #36: Add mandatory namespace to urls
* Issue #31: Add docstring to OAuthToolkitError and FatalClientError
* Issue #32: Add docstring to `validate_uris`
* Issue #34: Documentation tutorial part1 needs corsheaders explanation
* Issue #36: Add mandatory namespace to urls
* Issue #45: Add docs for AbstractApplication
* Issue #47: Add docs for views decorators


## 0.3.2 [2013-07-10]

* Bugfix #37: Error in migrations with custom user on Django 1.5

## 0.3.1 [2013-07-10]

* Bugfix #27: OAuthlib refresh token refactoring

## 0.3.0 [2013-06-14]

* [Django REST Framework](http://django-rest-framework.org/) integration layer
* Bugfix #13: Populate request with client and user in `validate_bearer_token`
* Bugfix #12: Fix paths in documentation

**Backwards incompatible changes in 0.3.0**

* `requested_scopes` parameter in ScopedResourceMixin changed to `required_scopes`


## 0.2.1 [2013-06-06]

* Core optimizations

## 0.2.0 [2013-06-05]

* Add support for Django1.4 and Django1.6
* Add support for Python 3.3
* Add a default ReadWriteScoped view
* Add tutorial to docs


## 0.1.0 [2013-05-31]

* Support OAuth2 Authorization Flows


## 0.0.0 [2013-05-17]

* Discussion with Daniel Greenfeld at Django Circus
* Ignition
