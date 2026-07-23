# ADR 0001 — Revision proposal: separate the *client principal* from the *client registration*

- **Status:** Design discussion — companion to #1723 (ADR 0001)
- **Scope:** Entity model only. This is a why/what argument, not an implementation
  plan. No migrations, DDL, field types, or sequencing here — those are out of scope
  by construction.
- **Target:** the 4.0-era model, where the whole entity model is on the table and the
  ADR can change. The near-term CIMD release ships pragmatically (Application
  required); nothing here blocks it.
- **Relationship to ADR 0001:** this does **not** overturn the ADR. `Authorization`
  and `Session` are the right entities and the reasoning that produced them is sound.
  The argument here is that the ADR applied that reasoning to two implicit concepts
  (durable consent, the OP session) and stopped one axis short: it left **the client**
  modelled as a single `Application` that silently carries two concepts. CIMD, and the
  federation/ephemeral clients behind it, are the forcing function that makes the
  third axis visible. The proposal is to *extend* the ADR's own method to the client
  axis.

---

## TL;DR

`Application` is doing two jobs at once:

1. **the client principal** — the stable identity (`client_id`) that tokens, grants,
   authorizations, introspection, revocation and audit are *attributed to*; and
2. **the client registration** — a provisioned, operator- or DCR-created record that
   holds authentication material (secret, signing key, confidential/public type) and
   administratively-managed policy (redirect URIs, grant types, name).

For manually created and DCR clients these two coincide, so the conflation has been
invisible. CIMD breaks the coincidence: its identity is a URL and its "registration"
is a document *fetched on demand* — derived, self-asserted, evictable. Because DOT can
only attribute a token to an `Application` **row**, CIMD is forced to mint
registration-shaped rows for things that are not registrations, on the unauthenticated
pre-auth path. Every consequence observed in the task — pre-auth DB writes,
attacker-mintable unbounded rows, the row doubling as metadata cache and dedup key —
is a symptom of concept (1) being unable to exist without a row of concept (2).

**Recommendation.** Make the durable client *identity* (`client_id`, a string) a
first-class attribute of `Authorization`, and demote the `Application` foreign key on
authorizations and tokens to an **optional** pointer to "the provisioned registration
backing this client, if any." A null registration then has a precise meaning —
*derived / ephemeral / deleted client* — while the principal remains fully identified
by `client_id`. CIMD and federation metadata become a **cache**, modelled and evicted
as a cache, never the token referent. This is the minimal change that lets token
issuance stop depending on a durable registration row while preserving everything
ADR 0001 already gets right.

DOT already has the precedent in tree: the device flow references its client by
`DeviceGrant.client_id` (a `CharField`), not by an `Application` FK.

Two independent checks, added after review, support this and are the backbone of the
argument: **Grounding A** shows the split is already present in the RFC/OIDC *domain
language*; **Grounding B** shows five of six mature OSS servers already model durable
client attribution exactly this way, and a sixth (WSO2) ships the principal/registration
separation itself.

---

## Grounding A — the RFC domain language already separates these concepts

The recommendation is not a new abstraction imposed on the specs; it is the vocabulary
the specs already use. Four points, quote-driven.

**A.1 — The corpus distinguishes *actor* / *identifier* / *metadata* / *credential* as
four different things.**

- *Client* (the actor) — RFC 6749 §1.2: "An application making protected resource
  requests on behalf of the resource owner and with its authorization," and "The term
  'client' does not imply any particular implementation characteristics."
- *Client identifier* (the handle) — RFC 6749 §2.2: "a unique string **representing the
  registration information** provided by the client," and "The client identifier is not
  a secret; it is exposed to the resource owner and MUST NOT be used alone for client
  authentication."
- *Client metadata* (the associated record) — RFC 7591 §2: "Registered clients have a
  set of metadata values **associated with their client identifier** at an authorization
  server, such as the list of valid redirection URIs or a display name."
- *Client credentials* (the secret) — the third, confidential-only thing (`client_secret`),
  distinct from both identifier and metadata.

The identifier *represents* / is *associated with* the registration — it **is not** the
registration. This is precisely the principal-vs-registration split, stated in the base
spec. `Application` collapses all four into one row; the specs never do.

**A.2 — Unregistered and derived-identity clients are explicitly contemplated.**

- RFC 6749 §2.4: "This specification does not exclude the use of unregistered clients.
  However, the use of such clients is beyond the scope of this specification…" — a
  principal without a provisioned registration is spec-sanctioned, merely left to
  profiles like CIMD/federation to define.
- CIMD (Abstract): identity "through the usage of a URL as a `client_id`… where the URL
  refers to a document containing the necessary client metadata, enabling the
  authorization server to **fetch** the metadata about the client as needed"; (Intro)
  "how an OAuth 2.0 client can **publish its own registration information and avoid the
  need for pre-registering**." The verbs are *fetch / retrieve / publish*, never
  *register*. §4 binds it: the document's `client_id` "MUST match the Client Identifier
  URL."
- OpenID Federation: a Relying Party is an *Entity* identified by an *Entity Identifier*
  — "A globally unique string identifier that is bound to one Entity. All Entity
  Identifiers… are URLs that use the https scheme"; its usable metadata is *Resolved
  Metadata* — "the metadata that results from applying the metadata policy in the Trust
  Chain to the metadata in the Entity Configuration." **Derived, not provisioned.**

*Correction to an earlier claim in this doc:* CIMD does **not** mandate public clients.
The spec precludes only a pre-established shared secret (there is no registration step to
set one); a CIMD client can still authenticate with an asymmetric method
(`private_key_jwt`). DOT's `cimd.py` *chooses* public-only. So invariant **I3**
(a client that cannot authenticate must not get `client_credentials`) stands, but
"CIMD ⇒ public" is a DOT implementation decision, not a spec rule.

**A.3 — "Authorization grant" is a *transient credential*; durable consent is undefined
in the corpus.** RFC 6749 §1.3: "An authorization grant is a **credential** representing
the resource owner's authorization… used by the client to obtain an access token." No
RFC in the set (6749/7591/8628/9700) defines a durable, queryable consent record — it is
out of scope everywhere. This is exactly the gap ADR 0001's `Authorization` fills, and it
is why every mature server had to invent it (Grounding B). It also vindicates the ADR's
non-renaming of `Grant`: the code *is* the grant credential (§1.3), while the durable
record is a different concept that deserves a different name.

**A.4 — The specific mechanisms the ADR targets are grounded verbatim.**

- Code-replay revocation — RFC 6749 §4.1.2: "If an authorization code is used more than
  once, the authorization server MUST deny the request and SHOULD revoke (when possible)
  **all tokens previously issued based on that authorization code**." That italicized set
  is precisely the lineage an `Authorization` makes reachable — grounding the phase-1
  `Grant.exchanged_at` + `Authorization.revoke()` cascade.
- Session / `sid` — Front-Channel Logout §1.2 defines *Session* ("Continuous period of
  time during which an End-User accesses a Relying Party relying on the Authentication of
  the End-User performed by the OpenID Provider") and *Session ID* ("Identifier for a
  Session"); the `sid` claim is "opaque to the RP" and "Its syntax is the same as an
  OAuth 2.0 Client Identifier." Note these live in the *logout* specs, **not** OIDC Core —
  a small precision the ADR can absorb. This grounds `Session` as a distinct entity
  carrying an opaque `sid`.

*Verification note:* the canonical hosts (rfc-editor.org, openid.net, datatracker) were
egress-blocked this session; OIDC/CIMD/Federation quotes were taken verbatim from the
specs' own GitHub sources, and the four RFC quotes from an exact-text search index. A few
phrasings could not be verbatim-confirmed and are therefore paraphrased above as
normative substance rather than quoted: RFC 6749 §2.3's opening sentence, RFC 7591's
per-field definitions, and RFC 9700 §4.14's exact wording on refresh-token-family
revocation. Confirm these against the published text before quoting them as verbatim.

---

## Grounding B — how six mature OSS servers actually model this

Source review of the client / consent / session models in six independent
implementations (entity, schema and mapping files read directly). The pattern is
strikingly uniform.

| Project | Client entity & PK | How durable consent/tokens reference the client | First-class durable consent? | Session model |
|---|---|---|---|---|
| **Spring Authorization Server** | `RegisteredClient`, PK `id` (string) ≠ `client_id` | `OAuth2Authorization.registeredClientId` (**String**); consent table keyed on `registered_client_id` — **no FK in the DDL** | **Yes** — `OAuth2AuthorizationConsent`, PK `(registered_client_id, principal_name)` | Spring Security session (not modeled in AS) |
| **Authlib** | `OAuth2ClientMixin.client_id` (String) | token & code mixins: `client_id = Column(String(48))`; `check_client()` compares the string — **no FK** | app-defined | — |
| **Keycloak** | `ClientEntity`, **surrogate** PK `ID` (uuid) ≠ `CLIENT_ID` | `USER_CONSENT.CLIENT_ID` and `OFFLINE_CLIENT_SESSION.CLIENT_ID` are **plain strings, no FK** (only `USER_ID` is a FK) | **Yes** — `USER_CONSENT` + `USER_CONSENT_CLIENT_SCOPE` | **two-level** `USER_SESSION → AUTHENTICATED_CLIENT_SESSION` |
| **IdentityServer4 / Duende** | `Client`, PK `int Id`, `ClientId` unique string | `PersistedGrant.ClientId` (**String**, `IsRequired`), PK is `Key` — **no FK to Client** | **Yes** — a `PersistedGrant` of `Type="user_consent"` | no server-side session table; `SessionId` **string** on the grant |
| **node-oidc-provider (panva)** | `Client` (`clientId`) | tokens carry `clientId` + `grantId` **strings** — no FK | **Yes** — first-class `Grant` model (`accountId, clientId, scopes, claims`) | `Session` (public `uid`, per-client `sidFor`/`grantIdFor`) |
| **WSO2 Identity Server** | **`SP_APP` (application principal)** *plus* `IDN_OAUTH_CONSUMER_APPS` (OAuth registration) | token → registration by **int FK** `CONSUMER_KEY_ID`; registration ↔ principal by **client_id string** (`SP_INBOUND_AUTH.INBOUND_AUTH_KEY`) | **Yes** — `CM_RECEIPT` (Kantara consent receipts) | `IDN_AUTH_SESSION_STORE` (+ per-app session info) |
| *(DOT today, for contrast)* | `Application` (swappable) | tokens/grants/`Authorization` → `Application` by **hard FK**; **no `client_id` on the durable records** | Yes — `Authorization` (ADR/Phase-1) | `Session` (ADR) |

What the survey establishes:

1. **Durable client attribution is done by a stable identifier *string*, not a FK to the
   registration row — in five of six.** Spring, Authlib, Keycloak, IdentityServer4 and
   panva all store the `client_id`/registered-client-id as a string on the consent/grant/
   token records with no database foreign key. Keycloak is especially telling: its client
   has a *surrogate* UUID PK distinct from `CLIENT_ID`, its consent FK-joins the **user**
   but references the **client by string**. **DOT is the outlier** — a hard FK to the
   swappable registration and *no identifier string* on the durable records. That is the
   exact coupling CIMD strains.
2. **First-class durable consent, separate from tokens, is near-universal.** Spring
   (`OAuth2AuthorizationConsent`), Keycloak (`USER_CONSENT`), IdentityServer4
   (`user_consent` grant), panva (`Grant`), WSO2 (`CM_RECEIPT`) all model it. Only Ory
   Hydra folds consent into its `hydra_oauth2_flow` row. This is strong, independent
   validation of ADR 0001's `Authorization` — and **Spring independently chose the exact
   same name** ("A representation of an OAuth 2.0 Authorization… state related to the
   authorization granted to a client").
3. **The "consumed/exchanged" marker on the code credential is prior art, not a DOT
   invention.** IdentityServer4's `PersistedGrant.ConsumedTime` and panva's `consumed`
   mixin are the same idea as Phase-1's `Grant.exchanged_at` (don't delete on exchange;
   mark it, keep it as replay evidence). Validates that decision and its §4.1.2 purpose.
4. **The two-level session→per-client structure the ADR describes is what Keycloak and
   panva already do.** Keycloak's `USER_SESSION → AUTHENTICATED_CLIENT_SESSION` and
   panva's `Session.authorizations[clientId]` (with a per-client `sid`) both realise
   "one session spanning many clients," and match the ADR's "RP participation is derived"
   stance.
5. **The principal-vs-registration split itself ships in production — WSO2.** A WSO2
   *Service Provider* (`SP_APP`, protocol-agnostic application identity) is deliberately
   separate from the OAuth *registration/credentials* (`IDN_OAUTH_CONSUMER_APPS`), joined
   by the `client_id` string; the OAuth registration's Java model literally
   `OAuthAppDO extends InboundConfigurationProtocol` — a registration is *one inbound
   protocol config* attached to the application. That is Model 2's north star, already
   built.

Honest boundaries of the prior art — where the recommendation is genuinely ahead of it:

- **FK is not forbidden by prior art.** Hydra references the client by a string that is
  *also* a DB foreign key (`hydra_client.id` is the `client_id`), and WSO2 uses an integer
  FK to the registration. The load-bearing move is *carrying the stable `client_id` on the
  durable records*; whether an **optional/nullable** `Application` FK is kept alongside is
  an integrity/convenience choice several projects make. This refines Model 4: **add
  `client_id` and keep the `Application` FK nullable — do not drop the FK** (that was
  Model 1's overcorrection).
- **Modeling derived-client metadata as an evictable *cache* rather than a registration is
  the least-attested part.** Where servers support URL/derived clients they mostly
  *auto-register*: Janssen resolves a CIMD URL and auto-creates a client; WSO2's
  SSA-seeded DCR still provisions a local `SP_APP` + consumer app. That is exactly DOT's
  current CIMD approach — and its problem (§0/§7 Model 0). So on cache-vs-registration the
  **specs** (CIMD "fetch"; Federation "Resolved Metadata") are the better guide than
  today's implementations, most of which have not separated the two yet.

**Net effect on the recommendation.** Model 4 is not a gamble: carrying `client_id` on
`Authorization` moves DOT onto the durable-attribution pattern that Spring, Authlib,
Keycloak, IdentityServer4 and panva already share; keeping a first-class `Authorization`
consent entity matches five of six (and Spring's naming); and the principal/registration
separation is WSO2's shipping design. The parts that stay DOT-specific — treating
derived-client metadata as a cache, not a registration — are precisely the parts the CIMD
and Federation specs point to directly.

---

## 1. What `Application` actually is today

Read `AbstractApplication` as a bag of responsibilities rather than a single concept
and it separates cleanly into five:

| # | Responsibility | Fields | True of which clients? |
|---|---|---|---|
| A | **Identity (principal)** | `client_id` | all — this is "who is asking" |
| B | **Authentication material** | `client_secret`, `hash_client_secret`, `algorithm`, `client_type` | confidential clients only |
| C | **Declared policy** | `redirect_uris`, `allowed_origins`, `post_logout_redirect_uris`, `authorization_grant_type`, `skip_authorization`, available scopes | all, but *source* differs |
| D | **Provenance / lifecycle** | `registration_source`, `cimd_expires_at`, `name`, `user` (developer/owner), `created`/`updated` | all |
| E | **Token/consent referent** | every FK from `Grant`, `AccessToken`, `RefreshToken`, `IDToken`, and (Phase 1) `Authorization` | all |

A is the *principal*. B–D are a *registration* — the durable, managed record of a
client. E is the *use* of the principal as an attribution target.

The design assumption baked into `Application` is that **A implies B–D implies a
row** — that to be a principal (A) you must be a provisioned registration (B–D) with a
persistent row (E). That is true for manual and DCR clients and false for every
derived-identity mechanism:

- **CIMD**: A is a URL; C is a *fetched document*; B is empty (public only); D is a
  *cache* (`cimd_expires_at`). There is no registration — there is a principal plus a
  cached metadata view.
- **OpenID Federation** (coming, same shape): A is an entity-identifier URL; C is
  *derived from a trust chain* + policy; B may be a federation key; D is again a cache
  of a resolved chain.
- **Ephemeral / no-registration public PKCE** (wanted by deployments): A is a
  self-asserted `client_id`; B empty; C minimal/none; D none.

CIMD's `cimd.py` shows the strain directly: `_fetch_validate_upsert` writes an
`Application` row on first sight from the authorize path, guards a client-vs-URL
collision by hand, and races two first-sight requests through an `IntegrityError`
handler — all machinery that exists only because a *cache entry* is being forced to
live in the *registration* table so that it can be a *referent*.

---

## 2. What each flow needs to know about "the client," and when

Trace the flows and ask two questions at each step: *what* client fact is needed, and
does it need to be **durable** (survives long after issuance), **transient** (lives for
one request), or **derived** (recomputable from the identity on demand)?

| Flow | Step that needs the client | What it needs | Durable / transient / derived |
|---|---|---|---|
| Auth code / hybrid | `/authorize` (pre-auth) | identity; redirect URIs; grant/response types; display name; consent policy | **derived** metadata is sufficient; nothing must be *written* here |
| " | `/token` exchange | authenticate (confidential) or identify (public+PKCE); re-check redirect URI; **attribute tokens** | attribution is **durable**; auth material is **durable** (secret can't be re-derived) |
| Implicit | `/authorize` | as above; tokens minted here, no code | metadata **derived**; attribution **durable** |
| ROPC | `/token` | authenticate/identify client; authenticate user | attribution **durable**; auth material **durable** |
| client_credentials | `/token` | **authenticate** the client — the client *is* the whole identity, there is no user | auth material **durable**; the "consent" is the registration itself |
| Device | `/device_authorization`, verification page, polling `/token` | identify client (already by `client_id` string); attribute tokens | attribution **durable** — and already keyed by `client_id`, not a row |
| Refresh | `/token` | identify client; check the refresh token belongs to it; attribute new tokens | attribution **durable** |
| CIMD | `/authorize` first sight | fetch + validate document; identity == URL; redirect URIs | metadata **derived** (cache); attribution **durable** |
| Federation | `/authorize` | resolve + validate trust chain; derive metadata | metadata **derived** (cache, cryptographically anchored); attribution **durable** |

Two conclusions fall out:

- **The only thing that must be durable about a client is (a) its authentication
  material, for confidential clients, and (b) the *attribution* of every token and
  authorization to a stable identifier.** Everything else the flows need — redirect
  URIs, grant types, display name — is *policy metadata* that can be stored, fetched,
  or trust-chain-derived, and for three of the five establishment mechanisms is not
  durable at all.
- **Attribution is durable, but the registration is not the only possible carrier of
  it.** The device flow already proves the principal can be carried as a `client_id`
  string. What tokens need at introspection/revocation/audit/logout time is "which
  client is this," which is the *identifier*, not a live registration row.

This is the whole case: attribution (durable) and registration (sometimes durable,
sometimes a cache) are different lifetimes, and coupling them via one FK forces the
shorter-lived thing to fake being the longer-lived thing.

---

## 3. The entities that fall out

ADR 0001 already named the two that were missing on the *token* side. Adding the
client-side distinction gives a complete set:

1. **Client principal** — identity `client_id`. The referent for authorizations and
   tokens. Not necessarily a managed row; for derived clients it is just the stable
   identifier plus a *kind* (how it was established).
2. **Client registration / metadata record** — today's `Application`, reframed as *one
   kind* of client metadata+credential record (the provisioned kind). Holds auth
   material and admin-managed policy. Optional backing for a principal.
3. **Client metadata cache** — for CIMD/federation, the fetched/derived document with a
   freshness bound. *Not* a registration, *not* a referent. Evictable without touching
   any token.
4. **`Authorization`** — durable consent + lineage anchor. **(ADR 0001 — correct, keep.)**
5. **`Session`** — OP authentication session per user agent, `sid`. **(ADR 0001 —
   correct, keep.)**
6. **`Grant` / `DeviceGrant`** — transient flow credentials. **(Keep.)**
7. **Access / Refresh / ID tokens** — **(Keep.)**

The pragmatic realization (see §5) does not require a literal new `Client` table for
(1); it requires that **the principal's identifier lives somewhere that does not
depend on a registration row** — concretely, on `Authorization`.

---

## 4. Invariants across all establishment mechanisms

What must hold no matter how a client was established (manual, DCR, CIMD, federation,
ephemeral):

- **I1 — Identity stability.** A `client_id` denotes exactly one principal for the
  lifetime of any token or authorization that references it. *Mechanism-specific* is
  how this is enforced: manual/DCR via a unique provisioned id; CIMD via the
  `document.client_id == fetch-URL` binding; federation via the trust chain to an
  anchor; ephemeral is the **weak** case — the id is self-asserted and unauthenticated,
  so I1 holds only within a request, not across time. That weakness is a property to
  *state*, not to paper over.
- **I2 — Redirect-URI trust.** Before any redirect, `redirect_uri` is validated against
  an authoritative set for the client. The *check* is identical across mechanisms; only
  the *source* of the set differs (stored / fetched / trust-chain-derived).
- **I3 — Auth capability gates flows.** A client either can authenticate (secret/key)
  or cannot. A client that cannot authenticate **must not** be issued a
  `client_credentials` grant. DOT's CIMD implementation is public-only and correctly
  forbids `client_credentials` (the CIMD spec itself permits asymmetric client auth —
  see Grounding A.2); the invariant must survive federation and ephemeral too.
- **I4 — Attribution durability.** Every issued token and every `Authorization` remains
  attributable to a stable client identifier for as long as it exists — *independent of
  whether the client's metadata record still exists.* This is the invariant the current
  single-FK model cannot express, and the one that most directly motivates the
  recommendation.
- **I5 — Consent is not retroactively widened by a metadata refresh.** A CIMD/federation
  document changing its `name`, `redirect_uris`, or declared grant types must affect
  *future* authorizations only. A past `Authorization` must reflect what was consented
  to *then*. (Today this is satisfied by snapshotting: `Authorization.scope` and
  `Grant.redirect_uri` are copies, not live reads. Preserve that discipline; do not
  "optimize" a token check into a live read of the mutable metadata record.)
- **I6 — No unauthenticated durable side effects on the pre-auth path.** Establishing a
  client's *metadata* must not, by itself, create attacker-controlled unbounded durable
  state. CIMD violates this today precisely because metadata and registration share a
  table; a cache with an eviction policy would satisfy it.

**Common to all mechanisms:** I1–I6, a principal identifier, a metadata view
(redirect URIs / grant types / display), and a public-vs-confidential determination.
**Mechanism-specific:** durability of the metadata (stored vs cached), the *trust
basis* (operator fiat / authenticated DCR / TLS-to-origin / cryptographic chain /
none), and the presence of auth material.

---

## 5. Optionality: every meaningful NULL, and what it means

ADR 0001 is emphatic that nullability is semantic, not transitional, and enumerates the
user/session cases. Extending the same discipline to the client axis, and reconciling
it with the existing token nulls:

| Reference | NULL means | Not "migration convenience" because |
|---|---|---|
| `Authorization.user` | client_credentials: no resource owner; consent is the registration | a client-only grant has genuinely no user, permanently |
| `Authorization.session` | non-interactive flow (ROPC, client_credentials) or a pre-Session row | those flows create no OP session by definition |
| token → `Session` (via `Authorization`) | `offline_access`, or a session-less flow | offline tokens are *defined* to outlive the session |
| `AccessToken.application` **today** | (a) external **introspected** token (`application=None` in the RS path) **or** (b) client row deleted | two distinct meanings already overloaded onto one NULL |
| **proposed** token/authorization → **registration** | **the client has no provisioned registration**: CIMD/federation/ephemeral, *or* the registration was deleted | the principal is still fully identified by `client_id`; the registration genuinely does not exist |

The last row is the point. If the client's identity lives **only** in the
`Application` FK, then a null FK is data loss — you no longer know who the token
belongs to, which is why the introspection path's `application=None` tokens are today
attributable to no client at all. If instead `client_id` lives on the `Authorization`,
a null registration FK is *lossless and meaningful*: "derived or deleted client, still
identified." This is the structural reason to carry the identifier separately from the
FK.

Note the overloading in the existing `AccessToken.application` NULL — flag it in review:
"external introspected token" and "deleted client" and (soon) "derived CIMD client"
are three different facts. Keep them distinguishable via `client_id` +
`registration_source`/kind rather than collapsing them into one ambiguous NULL.

---

## 6. A concrete inconsistency in the Phase-1 FK graph (evidence, not opinion)

The Phase-1 branch (`claude/adr-0001-phase1-authorization`) wires:

- `Authorization.application` → `on_delete=CASCADE`, **non-null**
- `AccessToken.authorization` / `RefreshToken.authorization` / `IDToken.authorization`
  → `on_delete=RESTRICT`, nullable

These two cannot both stand alongside the ADR's stated goal of *preserving token
history when a client is deleted*:

- Deleting an `Application` **cascades** into its `Authorization` rows.
- But each `Authorization` is **`RESTRICT`ed** by any token issued under it.
- So `Application.delete()` for any client with live tokens **raises and fails
  entirely** — you can neither delete the client nor preserve history.

The ADR's "positive" list and its `AccessToken.application` SET_NULL-for-history intent
point the other way: client deletion should *keep* the tokens and *null the client
pointer*. The clean resolution is exactly the recommendation: **`Authorization`
carries `client_id` durably; its registration FK is `SET_NULL` (or the registration is
simply never the identity).** Then deleting a registration nulls the pointer on the
authorization, the token→authorization `RESTRICT` still protects lineage, and the
principal survives as `client_id`. The inconsistency dissolves because the identity was
never in the FK to begin with.

(If the current phase-1 `CASCADE`/`RESTRICT` pairing is deliberate — "clients with live
tokens simply cannot be deleted" — that is a defensible policy, but it contradicts the
ADR's history-preservation wording and should be stated as the chosen semantics rather
than left as an accident of two independently-chosen `on_delete`s.)

---

## 7. Alternatives considered

**Model 0 — ADR/CIMD as shipping: `Application` required; derived clients mint rows.**
Uniform, one join, no new concepts, and it is the correct *pragmatic* choice for the
near-term CIMD release. As the *4.0 target* it institutionalises the conflation:
unauthenticated pre-auth writes (I6), attacker-mintable unbounded registration rows,
the registration table polluted with non-registrations (admin/DCR surfaces now list
cache entries), and the row forced to serve as cache + dedup key + referent
simultaneously. `registration_source` mitigates the *display* symptom but not the
structural one. **Reject as the target.**

**Model 1 — Reference the client by `client_id` string everywhere; drop the FK.**
Tokens/authorizations store `client_id`, like `DeviceGrant` already does. Derived
clients need no row. But this throws away referential integrity and cascade semantics
for the *registered* majority, and complicates admin inlines and the swappable-model
joins that downstream projects rely on. Correct instinct (identity is the string),
overcorrected. **Reject as stated, but keep its core.**

**Model 2 — First-class `Client` principal table + separate `Registration`.**
Introduce a thin `Client` (unique `client_id`, `kind`) as the referent; `Registration`
(≈ today's `Application`) optionally backs it with auth material + policy; CIMD/
federation get a metadata cache, not a registration. Conceptually the cleanest and the
honest target. Cost: a new swappable model in the hot path, and `Application` is
swappable **and** subclassed by essentially every downstream deployment — a literal new
referent table is the single most expensive migration DOT can ask for. **Right model,
wrong price for 4.0** — hold it as the north star, not the deliverable.

**Model 3 — Keep `Application` as referent; move only the cache out; add a `kind`.**
Stop overloading the row as the CIMD cache (separate the fetched document into a cache
store keyed by URL) and discriminate derived clients with a `kind`. Removes the
cache/dedup conflation and some row growth. But token issuance still depends on a
durable `Application` row on the pre-auth path (I6 only half-addressed), and the
attribution-durability problem (I4, §6) is untouched. **Partial.**

**Model 4 (recommended) — Carry `client_id` on `Authorization`; make the registration
FK optional.** `Authorization` gains a durable `client_id` (the principal) and treats
the `Application`/registration FK as an optional, `SET_NULL` back-reference meaning
"provisioned registration, if any." Tokens inherit attribution through their
`Authorization`. CIMD/federation metadata is a cache (Model 3's cache split), never the
referent; a derived client may have a null registration FK and still be fully
attributable. This is **Model 1's identity-is-the-string insight applied only where it
pays (the durable attribution point), without Model 2's new-referent-table cost**, and
it is realisable inside the swappable-model + backward-compat constraints because it
adds a column and relaxes a nullability/`on_delete`, rather than re-pointing every FK.

**Recommendation: Model 4, with Model 2 named as the eventual north star.** It resolves
every observed CIMD consequence (metadata becomes evictable cache → no pre-auth durable
writes, no attacker-mintable *registration* rows, no row-as-cache), fixes the §6
`on_delete` inconsistency, gives the introspection-path `application=None` tokens a real
identity for the first time, and leaves `Authorization`/`Session` exactly as ADR 0001
designed them.

---

## 8. Boundaries to hold in review — what NOT to merge or conflate

- **Registration ≠ principal.** A CIMD/federation cache entry is not an `Application` an
  operator provisioned. Do not surface it in DCR management or the admin "registered
  applications" list as if it were; discriminate by `registration_source`/kind. (The
  enum is already in tree — use it as a real type boundary, not a label.)
- **Metadata refresh ≠ consent change (I5).** Do not let `refresh_if_stale` or a trust-
  chain re-resolution retroactively alter what a past `Authorization` recorded. Keep the
  snapshot discipline (`Authorization.scope`, `Grant.redirect_uri` are copies). Never
  "optimize" a token-time check into a live read of the mutable metadata record.
- **Issuance ≠ a durable write on the pre-auth path (I6).** Issue against the `client_id`
  principal; the registration/cache lookup is a read (or a cache upsert with an eviction
  policy), never a prerequisite durable registration write triggered by an
  unauthenticated request.
- **One NULL ≠ three meanings (§5).** "External introspected token," "deleted client,"
  and "derived client" are different facts; keep them recoverable via
  `client_id` + kind, not collapsed into `application IS NULL`.
- **Authorization ≠ Session (ADR 0001's own line).** The client-axis split adds no
  temptation to merge these; keep the ADR's logout/revocation boundary intact.
- **The `Session` does not own the login (session axis — deferred).** Keep
  `Session.authenticated_at` sourceable from an external SSO, keep the Django-session
  correlation optional, and keep a pure introspecting resource server free of the new
  models. The full external-SSO modelling is out of scope here; the three guards that
  keep it from becoming a later breaking change are in §9.
- **AS-issued tokens ≠ RS cache entries (§10).** An RFC 7662 introspection result cached
  by a resource server is another AS's fact with a TTL, not a token this deployment
  issued. Do not let the new `authorization` FK acquire meaning on those rows, and do
  not let DOT's own introspection endpoint assert them as locally-issued.
- **Do not let "the FK exists" invent scope.** Same caution the ADR raises about
  `Authorization` growing session-ish behaviour applies to a client principal: it is an
  attribution anchor, not a place to hang policy that belongs on the registration or the
  authorization.

---

## 9. Session axis — out of scope here, but do not foreclose it

This revision is about the *client* axis. The parallel *session* axis — modelling an OP
authentication session that is established and owned by an **external SSO** (a Shibboleth
IdP session, a CAS ticket-granting ticket) rather than by the Django login — is
**deferred, not adopted here**. It surfaced in review (n2ygk, on #1723): "the concept of
a web SSO session [must not be] directly tied to a django session … if I perform a web
sso with … Shibboleth or CAS, that session can be used for a variety of Oauth2/OIDC and
non-oauth2 services." It is the session-axis twin of this document's client-axis argument
— an externally-established principal vs. a locally-owned record — and mature SSO systems
already model it as a protocol-agnostic session with per-service sub-sessions (Shibboleth
IdP session → per-SP sessions; CAS TGT → service tickets; cf. Keycloak's
`USER_SESSION → AUTHENTICATED_CLIENT_SESSION` and node-oidc-provider's per-client
`Session.authorizations` in Grounding B).

Building that is out of scope. But three cheap guards keep the door open so ADR 0001's
`Session` does not have to be redesigned later. None adds a feature; each only forbids a
shortcut that would turn the eventual external-SSO work into a *breaking* change instead
of an additive one.

- **`Session.authenticated_at` must be sourceable from an external authority**, not
  hard-wired to the Django login instant. In a federated deployment the real
  authentication happens upstream (e.g. at SAML assertion consumption), and today's
  `user.last_login`-derived `auth_time` is often *closer* to it than a DOT-minted session
  timestamp would be. Sourcing `authenticated_at` only from the local login would be a
  silent `auth_time` / `max_age` regression for SSO-fronted OPs — the opposite of the
  ADR's stated goal for that claim.
- **The Django-session ⇄ OP-`Session` correlation must stay optional, never
  definitional** (ADR 0001 Open Question 3). "The Django session was destroyed" is one
  possible signal that an OP session ended; it must not *be* the definition of the OP
  session, or a deployment whose authoritative session lives in Shibboleth/CAS inherits a
  session concept that is not the real one.
- **A resource-server deployment must not be forced to adopt the new *models*, and its
  token-table migration must be held to a single nullable column.** DOT's most common role
  in SSO shops (Columbia among them) is a pure RFC 7662 **introspecting resource server**:
  it mints no login session and issues no grants, but it **does store tokens** — the
  introspection cache writes each token into the `AccessToken` model (with
  `application=NULL`, and the Phase-1 path sets no `Authorization`). Two consequences the
  ADR must respect, because the "it's just a resource server, the schema won't touch it"
  intuition is only half true:
  - **The token-base FK column does reach them, and that is the unavoidable part.** Because
    the RS materialises `AccessToken` rows — and such deployments typically *swap* the
    concrete model (Columbia's `MyAccessToken` adds a `userinfo` field) — the new nullable
    `authorization` FK on `AbstractAccessToken` will appear on their model and force one
    migration. It must stay exactly that: a **nullable** column that is **NULL for
    introspected tokens**, never a required value and never a behavioural change on the
    introspection path.
  - **Being forced to define the new swappable models is the avoidable part, and it is a
    real risk, not a hypothetical.** Columbia already swaps *all four* token/application
    models and records in its own `models.py` that DOT's swappable-model interdependency
    *"seems to require creating swappable models even when no changes are needed to them."*
    If `Authorization` and `Session` inherit that same interdependency, a pure RS is dragged
    into defining two more swapped models (`OAUTH2_PROVIDER_AUTHORIZATION_MODEL` /
    `_SESSION_MODEL`) for zero benefit. The acceptance criterion is that it is not: the new
    models ship as inert defaults a resource server neither configures nor swaps.
  This is a Phase-1 packaging constraint, not a session-design one.

---

## 10. The RS introspection cache — same pattern, must be resolved before the schema is final

**Status: in scope as a consideration.** No design is committed here, but the 4.0 schema
must not be finalised without answering it, because it is the third instance of the
pattern this document exists to name — an externally-owned, evictable fact stored in a
durable authoritative table:

| Externally-owned fact | Table it squats in | Overloaded marker |
|---|---|---|
| CIMD / federation client metadata | `Application` | `registration_source`, `cimd_expires_at` |
| Derived client identity | `Application` (forced row) | `application IS NULL` after deletion |
| **RFC 7662 introspection result** | **`AccessToken`** | `application IS NULL` |

### Provenance — this was a known workaround, not a design

The introspection cache landed in PR #477 (2017, closing #342). The record is explicit:

- The author, on why the RS writes into `AccessToken`: "the Resource Server doesn't know
  about the applications on the Authentication Server, but creating an Access Token
  required an Application. Therefore I made `AccessToken.application` nullable so the RS
  can create Tokens without application," and "I'm using the existing DOT infrastructure
  to create Tokens (without Applications)."
- The reviewing maintainer, at merge: "this sounds like a **workaround rather than a
  solution** … I want to land this, but the AccessToken change is giving me pause."

So `application IS NULL` — the ambiguity §5 flags — is the direct sediment of that 2017
shortcut, and the concurrent first-sight race later patched in #611 is the same race
CIMD re-fought in its `IntegrityError` handler. The pattern reproduces its bugs.

### Scope of impact if split into a separate pipeline (surveyed, not assumed)

The consumer surface divides cleanly into two groups:

- **Interface-coupled (unaffected by a split, if the duck type is preserved).** DRF
  `OAuth2Authentication` returns `(r.user, r.access_token)`; the DRF permission classes
  (`TokenHasScope` and family) call only `is_valid()` / `is_expired()` /
  `allow_scopes()` on `request.auth`; `OAuth2Backend`, the `ProtectedResourceView`
  mixins and the decorators all consume the token via `verify_request` →
  `request.access_token`. None of these care which table — or whether any table — the
  object came from. A separate RS representation satisfying the same small interface
  slots in untouched.
- **Table-coupled (the real migration surface).** (a) The cache lookup itself
  (`_load_access_token` by `token_checksum`); (b) `clear_expired()`, which currently
  garbage-collects cache entries for free; (c) swapped-model extensions that hang data
  on the row — Columbia's `MyAccessToken.userinfo` is the live example, and it queries
  `AccessToken.objects` directly; (d) any deployment code that assumes introspected
  tokens appear in `AccessToken`.

**A finding that strengthens the split, found while surveying:** in a **dual AS+RS
deployment**, DOT's own introspection endpoint (`views/introspect.py`) looks up tokens
by `token_checksum` alone, with no filter on origin. Cached *external* tokens are
therefore served by DOT's introspection endpoint as if DOT had issued them — one
authorization server re-asserting another AS's token as "active" under its own
authority, with `application`/audience information missing. Sharing the table does not
just overload a NULL; it **conflates token authority** the moment a deployment wears
both hats.

### What must be decided before the schema is final

1. Whether the introspection result becomes its own evictable representation (cache
   entity or non-persisted object behind the existing duck type), or stays in
   `AccessToken` with its inapplicability to `authorization` explicitly documented.
2. If it stays: the new `authorization` FK must never acquire a meaning on RS rows —
   NULL there means "not applicable," and that is a *fourth* fact riding on the row.
3. If it splits: an extension point for RS-side per-token state (the Columbia `userinfo`
   pattern) must move with it, and `clear_expired()`'s cleanup duty must be reassigned.
4. Either way: the dual-role introspection leak above needs a decision — served,
   filtered, or documented — independent of where the cache lives.

The governing principle is the one this document applies to CIMD: **an externally-owned
cache is not an authoritative record, and must not be stored as one.** Whether the RS
cache is carved out in 4.0 or explicitly grandfathered, the schema should say which — by
decision, not by inheritance from a 2017 workaround its own reviewer flagged.

---

## 11. Open questions

1. **Table or column?** Is a literal `Client` principal table (Model 2) worth the
   swappable-model churn in 4.0, or is `client_id`-on-`Authorization` + optional
   registration FK (Model 4) sufficient? (Leaning Model 4; Model 2 as north star.)
2. **Where does derived metadata live** once it is no longer the `Application` row — a
   cache backend, or a durable `ClientMetadata` record keyed by URL/entity-id — and what
   is its eviction/GC story now that it is decoupled from token lifetime?
3. **Federation freshness.** Is the trust chain re-evaluated per authorization or cached
   like CIMD, and what are the I5 consent implications of each?
4. **Ephemeral clients and I1.** Do no-registration public PKCE clients get an
   `Authorization` at all, and what identifies them at revocation time given the
   `client_id` is self-asserted and not unique over time? (This is the mechanism where
   I1 is genuinely weak; decide and document the guarantee rather than implying a strong
   one.)
5. **One migration wave.** The ADR wants all schema to land together to halve downstream
   churn. If Model 4 is accepted, making `Authorization.application` nullable and adding
   `client_id` belongs in the *same* 4.0 wave as the Phase-1 `Authorization` schema — so
   that CIMD/federation do not force a second wave. Should the phase-1 non-null
   `Authorization.application` be relaxed *now*, ahead of the features that need it?
6. **Reconcile the §6 `on_delete` graph** explicitly: is client deletion meant to
   preserve token history (→ `SET_NULL` + durable `client_id`) or to be blocked while
   tokens live (→ current `CASCADE`/`RESTRICT`)? Pick one and write it down.
7. **AS-issued token ≠ RS cache entry (§10).** Decide before the schema is final whether
   the RFC 7662 introspection result stays in `AccessToken` (grandfathered, with
   `authorization` documented as never-applicable there) or becomes a separate evictable
   representation behind the existing token duck type. Survey says the DRF/backends
   surface is interface-coupled and safe; the migration cost is `_load_access_token`,
   `clear_expired()`, and swapped-model extensions like Columbia's `userinfo`. The
   dual-role introspection leak (§10) needs a ruling either way.
8. **Resource-server packaging (§9).** Confirm a pure introspecting resource server can
   run on the Phase-1 schema without being *forced* to define
   `OAUTH2_PROVIDER_AUTHORIZATION_MODEL` / `OAUTH2_PROVIDER_SESSION_MODEL` — specifically
   that the swappable-model interdependency which today forces swapping unchanged models
   (per Columbia's `models.py`) does **not** extend to the two new models — and that the
   only schema such a deployment inherits is the nullable, stays-NULL `authorization` FK
   column on the token tables it already stores into (the introspection cache). If it
   forces more than that column, defer the schema.
