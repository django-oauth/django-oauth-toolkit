# IDP Compliance & Competitive Comparison

**How Django OAuth Toolkit (DOT) compares to other OAuth 2.0 / OpenID Connect providers and
libraries, spec by spec and profile by profile.**

*Last verified: **2026-07**. Point-in-time snapshot — see [caveats](#caveats--disclaimer).*

> This folder is competitive positioning material and **names third-party products**. It is
> deliberately **not** part of the published Sphinx documentation site. For the neutral,
> vendor-free "what standards does DOT implement" reference, see
> [`docs/compliance.rst`](../docs/compliance.rst).

---

## The organizing model (why there are four tables, not one)

The hard part of a comparison like this is that you're juggling **three** things —
individual specs, named suites/profiles, and competitors — but a table only has two axes.
They separate cleanly once you notice:

> **Specs and suites are the same axis at two zoom levels.** A *suite* (OAuth 2.1, OIDC,
> FAPI, MCP) is just a **named bundle of specs** with mandatory/optional/forbidden rules
> layered on. *Competitors* are the genuinely separate axis.

So instead of one overloaded grid, this comparison is **four linked tables**:

| # | Table | Rows × Columns | Answers |
|---|---|---|---|
| 1 | [Spec × Competitor](./idp-op-comparison.md) | specs × products | "Who implements RFC X?" |
| 2 | [Suite → Spec membership](./suite-membership.md) | specs × suites | "What *is* OAuth 2.1 / FAPI / MCP?" (definitions) |
| 3 | [Suite × Competitor rollup](./suite-rollup.md) | suites × products | "Does product Y meet profile Z?" |
| 4 | [RP comparison](./rp-comparison.md) | RP capabilities × client libs | "Which *client* library should I use?" |

**"Should suites also be rows?"** — Yes, in **Table 3**, which aggregates Table 1 through the
definitions in Table 2. Keeping the suite rollup *separate* from the per-spec detail is what
avoids double-counting (a suite row and its member-spec rows can't live in the same grid).

**Two roles, two categories.** OAuth/OIDC has distinct roles. DOT is a **Provider /
Authorization Server (OP/AS)** and resource server — so Tables 1–3 compare it against other
*servers*. The **Relying Party (RP)** is the *client* role (logging users in *via* an IdP);
that's a different product category, so it gets its own **Table 4** with client-library
competitors, where DOT correctly shows as **N/A**.

---

## Who's compared

**Providers (Tables 1 & 3)**

- *Open-source libraries / engines:* **Django OAuth Toolkit** (this project),
  [oauthlib](https://github.com/oauthlib/oauthlib) (the engine DOT builds on),
  [Authlib](https://authlib.org/), [Authentik](https://goauthentik.io/)
- *Open-source IdP servers:* [Keycloak](https://www.keycloak.org/),
  [Ory Hydra](https://www.ory.sh/hydra/), [WSO2 Identity Server](https://wso2.com/identity-server/),
  [Zitadel](https://zitadel.com/), [Janssen / Gluu](https://jans.io/)
- *Commercial SaaS:* [Okta](https://developer.okta.com/), [Auth0](https://auth0.com/),
  [Microsoft Entra ID](https://learn.microsoft.com/entra/identity-platform/),
  [Ping Identity](https://www.pingidentity.com/)

**Relying-party libraries (Table 4)**

django-allauth, mozilla-django-oidc, Authlib (client), python-social-auth, Auth.js/NextAuth,
oidc-client-ts, passport-openidconnect, Spring Security OAuth2 Client.

---

## Legend

**Support (Tables 1, 3, 4)**

| Mark | Meaning |
|:---:|---|
| ✅ | Full — implemented (and certified where a certification exists) |
| ⚙ | Opt-in — implemented in DOT but off by default (behind a setting) |
| ◑ | Partial / limited / manual wiring |
| 🧩 | Add-on, plugin, or paid/enterprise tier |
| ❌ | None / not applicable to that product's role |
| ❓ | Unverified — no primary source could confirm it (do **not** read as "no") |
| N/A | Role doesn't apply (e.g. DOT in the RP table) |

**Membership (Table 2)**: ● required · ○ optional/recommended · ⊘ forbidden · *(blank)* not
in the profile.

---

## Methodology

- **The DOT column is authoritative.** It is scored directly from this repository's source
  (grants in `oauth2_provider/models.py`, validators, views, settings) and mirrors
  [`docs/compliance.rst`](../docs/compliance.rst). DOT delegates most protocol logic to
  **oauthlib** and JWT/JWK to **jwcrypto**, which is why oauthlib is scored as its own column.
- **Every other column is externally sourced** from primary references: each vendor's own
  documentation and source, and the
  [OpenID Foundation certification directory](https://openid.net/certification/) for OIDC
  and FAPI conformance. Certification (a third-party-verified claim) is treated as stronger
  evidence than a docs assertion.
- **Suites (Table 2)** are defined from the profile specifications themselves —
  [OAuth 2.1 draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/),
  [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html),
  [MCP authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization),
  and RFC 8252 — not from any vendor.
- **Conservative scoring.** Where sources conflicted or a claim couldn't be confirmed against
  a primary source, the cell is **◑** or **❓** rather than an optimistic ✅.

---

## Caveats & disclaimer

- **Point-in-time.** This reflects product state around **2026-07**. OAuth/OIDC support moves
  fast (DPoP, PAR, resource indicators, and MCP support in particular are actively shipping);
  re-verify before quoting.
- **Not a certification.** Only the OpenID Foundation can certify conformance. "✅" here means
  "implements per our reading of primary sources," not "certified" unless the row says so.
- **Editions differ.** Commercial products vary by tier/edition; "🧩" flags features gated
  behind enterprise/regulated plans, but exact packaging changes over time.
- **Some cells are `❓`.** During research the OpenID certification directory and several
  vendor doc sites intermittently blocked automated access; affected cells are marked ❓ and
  should be confirmed manually against a live `/.well-known/openid-configuration` or the
  certification directory.
- **No warranty.** This is engineering/marketing reference material, not legal or compliance
  advice.

An interactive, sortable version of these tables is available as
[`index.html`](./index.html).
