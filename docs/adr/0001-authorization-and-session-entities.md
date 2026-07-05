# ADR 0001: Authorization and Session entities in the token model

- **Status:** Draft — for discussion
- **Deciders:** django-oauth-toolkit maintainers
- **Date:** 2026-07-05
- **Related:** #1545 (OIDC Back-Channel Logout, milestone 3.4.0)

## Summary

Introduce two new swappable models that reify concepts DOT currently leaves
implicit:

1. **`Authorization`** — a durable record of granted consent: *user U (or
   client C alone) authorized application A for scopes S at time T via grant
   type G*. Created by **every** flow that issues tokens. Tokens and
   flow-specific credentials (authorization code, device code) reference it.
2. **`Session`** — the OP authentication session: *user U is logged in on
   user agent UA*. Identified by a UUID `sid` issued in ID tokens, correlated
   with (but distinct from) the Django session. Interactive `Authorization`s
   reference it.

These are orthogonal axes over the existing token chain. `Authorization`
answers *"which act of consent produced these tokens"*; `Session` answers
*"who is logged in, where"*. They are never merged, and revoking one is not
the same operation as ending the other.

## Context

### What DOT records today

- **`Grant` models one kind of authorization grant — the code — and nothing
  durable.** The name is spec-accurate for the code flow (RFC 6749 §1.3.1:
  the authorization code *is* the grant credential), but the other flows'
  grant credentials, and the granted consent they all represent, are not
  modeled. The row is created only in `_create_authorization_code()`
  (auth-code and hybrid flows) and **deleted** at token exchange by
  `invalidate_authorization_code()`. Nothing can reference it after the
  ~60 seconds it lives.
- **`DeviceGrant` is a second flow-specific credential table** (the
  `device_code`), not unified with `Grant`.
- **Implicit, Resource Owner Password Credentials (ROPC), and
  client_credentials leave no record** of the authorization at all.
- **No token carries lineage.** DOT cannot answer "which tokens were issued
  under which authorization." Consequences:
  - RFC 6749 §4.1.2 (and RFC 9700 §4.5) say a replayed authorization code
    SHOULD revoke all tokens previously issued on it. Because the code row
    is deleted, a replayed code is indistinguishable from an unknown code
    and the revocation is unimplementable.
  - `RefreshToken.token_family` exists solely to approximate lineage for
    rotation-reuse detection, and only within one refresh chain.
- **Consent memory is an access-token scan.** `AuthorizationView` with
  `require_approval="auto"` skips the consent screen iff an *unexpired
  access token* for user×application covers the requested scopes. Consent is
  remembered exactly as long as the newest access token lives.
- **There is no session model.** The OP session is the Django session,
  anonymously. Nothing in the token model references it and it has no
  identifier that could appear in a token. Consequences:
  - No `sid` claim in ID tokens, so OIDC Front-Channel and Back-Channel
    Logout (#1545) are unimplementable in their session-scoped form.
  - RP-initiated logout cannot scope revocation to "the session the
    `id_token_hint` belongs to," so `do_logout()` deletes **all** of the
    user's tokens across all applications and devices, while Django sessions
    in *other* browsers survive. Over-broad and under-broad at once.
  - `auth_time` in ID tokens is taken from `user.last_login`, which is
    user-global: logging in on a phone silently refreshes the `auth_time`
    asserted to RPs in a laptop's session, which breaks `max_age`
    semantics.

### What the specs say

- **RFC 6749 §1.3** defines an *authorization grant* as "a credential
  representing the resource owner's authorization … used by the client to
  obtain an access token." Every flow has one: the code, the user's
  password (ROPC), the client's own credentials, the device code (RFC 8628
  is titled "Device Authorization Grant"), assertions (RFC 7521/7523), and
  the refresh token acting as the grant at the token endpoint. DOT's `Grant`
  and `DeviceGrant` models reify two of these credentials, correctly named;
  the remaining flows' grants — and the durable consent that every grant
  credential represents — have no model.
- **No OAuth RFC defines a durable consent record.** It is deliberately out
  of scope, and every mature implementation invented it independently:
  Keycloak `UserConsent`, Ory Hydra consent sessions, Okta's Grants API.
  `Authorization` is DOT's version of that entity.
- **OIDC Front-/Back-Channel Logout** define a *session* as the continuous
  period during which an End-User is authenticated at the OP **via a
  particular user agent**, identified by the `sid` claim. It is created at
  login (not at authorization), spans all RPs the user signs into during
  that browser session, and its lifetime is decoupled from token lifetime
  in both directions — `offline_access` refresh tokens are *defined* as
  tokens that outlive it, and implicit/`id_token`-only responses produce
  sessions with no refresh token at all.
- Mature OPs converge on the same two-level structure: Keycloak
  `UserSession` → `AuthenticatedClientSession` → tokens; Hydra login session
  (`sid`) → consent → tokens; IdentityServer server-side session → client
  participation list → grants.

## Decision

### Target entity-relationship model

```mermaid
erDiagram
    User ||--o{ Session : ""
    User |o--o{ Authorization : "NULL for client_credentials"
    Application ||--o{ Authorization : ""
    Session |o--o{ Authorization : "NULL for non-interactive flows"
    Authorization |o--o| Grant : "code credential"
    Authorization |o--o| DeviceGrant : "device credential"
    Authorization |o--o{ AccessToken : ""
    Authorization |o--o{ RefreshToken : ""
    Authorization |o--o{ IDToken : ""
    RefreshToken |o--|| AccessToken : "existing 1:1"
    AccessToken |o--|| IDToken : "existing 1:1"

    Session {
        uuid sid UK "issued as the sid claim"
        fk user ""
        string session_key "nullable; Django session correlation"
        datetime authenticated_at "per-session auth_time"
        datetime expires ""
        datetime terminated_at "nullable"
        string termination_reason "logout / rp_logout / expired / admin"
    }
    Authorization {
        fk user "nullable"
        fk application ""
        fk session "nullable"
        string grant_type "how consent was expressed"
        text scope ""
        datetime created ""
        datetime revoked_at "nullable"
    }
```

Three tiers plus one orthogonal axis:

| Tier | Models | Lifetime | Role |
|---|---|---|---|
| Credential | `Grant` (auth code), `DeviceGrant` (device code) | seconds–minutes | RFC 6749 "authorization grant" credentials, flow-specific |
| Authorization | `Authorization` (new) | until revoked / retention limit | durable consent record; token lineage anchor |
| Tokens | `AccessToken`, `RefreshToken`, `IDToken` | as configured | unchanged |
| Session axis | `Session` (new) | login → logout/expiry | OP authentication session per user agent; `sid` |

### `Authorization` (new swappable model)

Fields: `id`, `user` (FK, **nullable**), `application` (FK), `session` (FK,
**nullable**), `grant_type`, `scope`, `created`, `updated`, `revoked_at`
(nullable).

Creation — one hook per flow:

| Flow | When an `Authorization` is created | `user` | `session` |
|---|---|---|---|
| Authorization code / hybrid | at approval in `AuthorizationView`; the `Grant` (code) row carries the FK and hands it to tokens at exchange | set | set |
| Implicit | at approval in `AuthorizationView` (same UI); tokens FK it directly — note implicit never creates a `Grant` row, which is why lineage cannot hang off the code table | set | set |
| Device (RFC 8628) | at user approval on the verification page; `DeviceGrant` FKs it | set | set (the verification-page browser session) |
| ROPC | at token issuance — one per password login; each is a distinct authorization event | set | NULL |
| client_credentials | `get_or_create` **one per application** with `user=NULL`; the consent is the client registration itself, and M2M clients requesting tokens in a loop must not mint a row per request | NULL | NULL |
| Refresh token grant | **never** — refreshed tokens inherit the parent `Authorization`, matching the RFC semantics of refresh as re-presentation of the original grant | — | — |

What this replaces or fixes:

- **Token lineage / replay revocation.** `Grant` gains `exchanged_at`
  (nullable) and is **no longer deleted** at exchange;
  `invalidate_authorization_code()` stamps it instead. A code presented
  twice is now detectable, and revocation cascades through its
  `Authorization` to all descendant tokens (RFC 6749 §4.1.2, RFC 9700).
- **`token_family` is subsumed** for all flows — a rotation family is
  exactly "refresh tokens under one `Authorization`," including ROPC where
  no code exists. The field is retained and deprecated; reuse-detection
  logic can migrate to the FK.
- **Consent memory becomes real.** `require_approval="auto"` checks for an
  unrevoked `Authorization` covering the requested scopes instead of
  scanning live access tokens, decoupling consent lifetime from token
  lifetime. An "authorized apps" management surface and revoke-by-app fall
  out of the same table.

### `Session` (new swappable model)

Fields: `id`, `sid` (UUID, unique, default `uuid4`), `user` (FK),
`session_key` (nullable, indexed), `authenticated_at`, `created`, `updated`,
`expires`, `terminated_at` (nullable), `termination_reason` (choices).

Semantics and plumbing:

- **Minted lazily** at the first authorization request after login: generate
  a UUID, persist the row, store the `sid` in `request.session`, reuse for
  subsequent authorizations in the same browser session. Plumbed from the
  view (which has `request.session`) into the validator via the existing
  `OAuthLibCore._get_extra_credentials()` hook — no oauthlib changes needed.
- **The Django `session_key` is not the `sid`.** The session key is the auth
  cookie value (secret, must not appear in an ID token) and rotates at
  login. The `sid` is a distinct UUID stored *in* the session; `session_key`
  is kept only as an optional correlation aid (e.g. terminating the OP
  session when the Django session is destroyed).
- **A DB row, not just session state**, because back-channel logout must
  answer "which RPs participated in this session" *after* the Django session
  is gone, and cache-backed session stores are not queryable.
- **ID tokens carry the `sid` claim**; `auth_time` moves from
  `user.last_login` to `Session.authenticated_at`, fixing the parallel-login
  `max_age` bug.
- RP participation in a session is **derived** (`distinct` over the
  session's `Authorization`s / ID tokens); no per-(session × application)
  join table until back-channel delivery/retry state forces one.

### Logout and revocation semantics

Stated explicitly because it is the pair most at risk of being conflated:

- **Revoking an `Authorization`** kills its token chains on every device.
  It does not log anyone out.
- **Terminating a `Session`** logs the user agent out: it ends the Django
  session, revokes the session's token chains **except** those with
  `offline_access`, and (once implemented) notifies participating RPs via
  back-channel logout. It does not touch the user's other browsers, other
  sessions, or offline grants.

RP-initiated logout becomes `id_token_hint → sid → terminate that session`,
behind a setting; the current revoke-everything behavior remains the default
until a deprecation cycle completes.

### Nullability is semantic, not transitional

All new FKs are nullable **permanently**: client_credentials and ROPC tokens
have a session-less existence; client_credentials has a user-less one;
`offline_access` refresh tokens legitimately outlive their session; and
pre-migration rows have no history to backfill (they are treated as
authorization-less and session-less; `sub`-only back-channel logout still
covers them). NULL means "this axis does not apply."

### Naming

The existing `Grant` model is **not renamed**. `OAUTH2_PROVIDER_GRANT_MODEL`
and downstream subclasses make a rename a gratuitous break, and "grant" for
the code table is the most literal RFC 6749 reading — the code *is* the
grant credential for that flow. The new entities are `Authorization` and
`Session` (both swappable, `OAUTH2_PROVIDER_AUTHORIZATION_MODEL` /
`OAUTH2_PROVIDER_SESSION_MODEL`), with docs clarifying the distinction.

### Cleanup

`cleartokens` learns two new steps with strict ordering: purge terminated /
expired `Session`s, and purge revoked / dormant `Authorization`s **only
after** their token chains are gone (the FKs are `SET_NULL`; purging early
would silently discard the lineage this ADR exists to create). Retention
windows are settings.

## Alternatives considered

- **Refresh token as the session anchor (status quo de facto).** Rejected:
  flows without refresh tokens still create sessions; `offline_access`
  refresh tokens must outlive the session by definition; one session spans
  many refresh tokens across RPs; the `sid` must be minted into the ID token
  at authentication time while refresh token identity rotates and never
  appears in ID tokens.
- **A persistent `Grant` as the session anchor.** Rejected: a grant is per
  (user × client); a session is per (user × user agent) and spans clients.
  Grant-scoped logout both misses the session's other RPs and kills the
  same RP's other-device grants. Grants and sessions also have independent
  lifetimes (`offline_access`).
- **Two-tier model: persist `Grant` and hang tokens off it (no
  `Authorization`).** Rejected after review: implicit flow issues tokens
  with no code row, ROPC/client_credentials have no code at all, and the
  device code lives in a different table — lineage anchored on the code
  credential covers only some flows. Reifying the abstract concept covers
  all of them uniformly and lets `session` live in exactly one place
  instead of being denormalized onto every token table.
- **Using the Django session key as the `sid`.** Rejected: it is the auth
  cookie value (secret), rotates at login, and cache-backed session stores
  cannot be enumerated at logout time.
- **Implementing OIDC Session Management 1.0 (`check_session_iframe`).**
  Out of scope: effectively dead due to third-party cookie blocking.
  Back-channel logout is the future-proof mechanism; front-channel is an
  optional cheap extra.

## Consequences

### Positive

- RFC 6749 §4.1.2 / RFC 9700 code-replay revocation becomes implementable.
- #1545 back-channel logout becomes implementable (`sid` + participation
  lookup); front-channel logout becomes possible.
- RP-initiated logout can be correctly scoped to one session.
- Consent memory decoupled from access-token lifetime; "authorized apps"
  UI and revoke-by-app enabled.
- Correct per-session `auth_time` / `max_age` semantics.
- `token_family` unified under a first-class concept for all flows.

### Negative / risks

- Two new swappable models and new FKs on the abstract token bases: every
  downstream project with concrete custom models eats a `makemigrations`
  cycle. Mitigation: land **all** schema in one release wave (nullable,
  inert additions), even though the features ship across releases.
- `Grant` rows persist after exchange: table growth, handled by
  `cleartokens`; deployments with custom `invalidate_authorization_code`
  overrides keep working but silently lose replay detection (docs note).
- One extra row write per interactive authorization and per ROPC login.
- Scope-creep risk: `Authorization` will tempt session-ish behavior (e.g.
  scoping logout by authorization "since the FK exists"). The logout
  semantics section above is the line to hold in review.

## Implementation sequencing

- **Phase 0 — this ADR.** Agree the entities, FKs, nullability, and
  semantics above. Phases 1 and 2 are independent once this is fixed.
- **Phase 1 — `Authorization` (fixing what exists).** New model + per-flow
  creation hooks; `Grant.exchanged_at` replaces delete-on-exchange; token
  and credential FKs; replay-triggered revocation; `cleartokens`; optionally
  switch `require_approval="auto"` to consult `Authorization`. Pure OAuth
  value, no OIDC concepts, and it exercises the swappable-model migration
  machinery on the axis that carries no new semantics.
- **Phase 2 — `Session`.** New model, lazy minting, `sid` claim,
  `session` FK on `Authorization`, `auth_time` from the session. Additive;
  no behavior change.
- **Phase 3 — payoff features.** Session-scoped RP-initiated logout behind
  a setting; back-channel logout (#1545); `offline_access` survival policy;
  optional front-channel logout.

Schema packaging: prefer landing Phase 1 + 2 migrations in a single release
to halve downstream migration churn, even if Phase 2/3 features ship later.

## Open questions

1. **client_credentials granularity** — one `Authorization` per application,
   or per (application × scope set)? Per-application with a scope superset
   is proposed above; per-scope-set gives cleaner audit at the cost of row
   churn.
2. **Consent presentation** — per-event `Authorization` rows are proposed
   (clean lineage, audit trail); an "authorized apps" UI then derives
   current consent as the union of unrevoked rows. Is a separate durable
   `Consent` (user × app) table wanted later, or is derivation enough?
3. **Does terminating a Django session terminate the OP `Session`?**
   Correlation via `session_key` makes it possible (e.g. a logout signal
   handler); is that Phase 2 or Phase 3?
4. **Retention defaults** for terminated `Session`s and revoked
   `Authorization`s before `cleartokens` purges them.
5. **`require_approval="auto"` switch** — Phase 1 (proposed) or deferred to
   its own release with a setting?
