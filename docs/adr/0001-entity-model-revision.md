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
  `client_credentials` grant. CIMD is public-only and correctly forbids
  `client_credentials`; the invariant must survive federation and ephemeral too.
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
- **Do not let "the FK exists" invent scope.** Same caution the ADR raises about
  `Authorization` growing session-ish behaviour applies to a client principal: it is an
  attribution anchor, not a place to hang policy that belongs on the registration or the
  authorization.

---

## 9. Open questions

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
