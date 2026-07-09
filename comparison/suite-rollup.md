# Table 3 — Suite × Competitor rollup (profiles as rows)

> Part of the [IDP compliance & competitive comparison](./README.md). Last verified **2026-07**.

This is the **summary heat-map**: each row is a *profile / suite*, each column a product, and
each cell a rollup of how well that product covers the suite's **required** specs. It is
**derived** — the required specs come from [Table 2 (membership)](./suite-membership.md) and
the per-spec support from [Table 1 (detail)](./idp-op-comparison.md). This is where your
"should suites be rows?" question lands: **yes — here, in the aggregate view**, never mixed
into the per-spec detail table (that would double-count).

## Legend

✅ **Strong** — meets the suite's required specs (certified where a certification exists) ·
◑ **Partial** — core present, one or more required pieces missing/gated · 🧩 **Add-on** —
achievable only on a paid/enterprise tier · ❌ **Gaps** — key required specs absent ·
**N/A** — role doesn't apply

Column keys: **DOT** · **oalib** = oauthlib · **Alib** = Authlib · **Autk** = Authentik ·
**KC** = Keycloak · **Hyd** = Ory Hydra · **WSO2** · **Zit** = Zitadel · **Jans** = Janssen ·
**Okta** · **Au0** = Auth0 · **Entra** · **Ping**.

| Suite | DOT | oalib | Alib | Autk | KC | Hyd | WSO2 | Zit | Jans | Okta | Au0 | Entra | Ping |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **OAuth 2.0** (classic) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ◑ | ✅ |
| **OAuth 2.1** (draft) | ◑ | ◑ | ◑ | ◑ | ✅ | ✅ | ◑ | ✅ | ◑ | ◑ | ◑ | ◑ | ◑ |
| **OIDC** (Core+Discovery) | ✅ | ◑ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Native apps** (RFC 8252) | ◑ | ◑ | ◑ | ◑ | ◑ | ✅ | ◑ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **FAPI 2.0** | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ◑ | ❌ | 🧩 | ❌ | ✅ |
| **MCP authorization** | ◑ | ❌ | ❌ | ❌ | ◑ | ❌ | ◑ | ❌ | ◑ | ❌ | ◑ | ❌ | ◑ |
| **RS** (resource-server role) | ✅ | ◑ | ✅ | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| **RP** (client role) | N/A | N/A | ◑ | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |

*The last two rows are separate **roles**, not provider profiles. **RS** (resource server):
DOT itself protects APIs (✅), oauthlib gives building blocks (◑), Authlib ships a
ResourceProtector (✅) — the rest are providers, compared as RS products in
[Table 5](./rs-comparison.md). **RP** (client): only Authlib ships a client here (◑); DOT is
N/A — see [Table 4](./rp-comparison.md).*

## How each verdict is reached (gating specs)

- **OAuth 2.0** — core framework (6749) + bearer (6750), with the common extensions (PKCE,
  revocation, introspection). Everyone here clears it; Entra is ◑ only because it omits the
  standard revocation and introspection endpoints.
- **OAuth 2.1** — PKCE mandatory + the implicit/password grants removable + Security-BCP
  alignment. ✅ goes to servers with an explicit 2.1 posture (Keycloak's 2.1 client profile,
  Hydra's OAuth-2.1 mode, Zitadel's no-ROPC/PKCE-first design). Everyone else is ◑: PKCE is
  on, but the legacy grants remain available and there's no named 2.1 mode. **DOT is ◑** —
  its defaults already align (PKCE required by default), but implicit and password grants
  ship enabled and there is no 2.1 switch.
- **OIDC** — OIDC Core + Discovery (+ JWT ID tokens). Every dedicated server/SaaS is
  OpenID-certified here; **DOT is ✅ but opt-in and *not* certified**, oauthlib is ◑
  (flows only, no discovery).
- **Native apps** — RFC 8252 + PKCE + external user-agent. ✅ where the vendor documents the
  native-app BCP; ◑ where only the PKCE building block is present.
- **FAPI 2.0** — the demanding one: PAR + sender-constraining (mTLS **or** DPoP) +
  private_key_jwt + metadata, usually with certification. ✅ = certified/conformant
  (Keycloak, WSO2, Ping); ◑ = FAPI 1.0 only (Janssen); 🧩 = enterprise add-on (Auth0);
  ❌ = missing prerequisites (**DOT and the leaner servers**).
- **MCP authorization** — OAuth 2.1 + Protected Resource Metadata (9728) + resource
  indicators (8707) + AS metadata, DCR recommended. **Nascent industry-wide**: 9728 is
  barely implemented anywhere, so the best anyone scores today is ◑ (has resource
  indicators and/or experimental MCP resource-server support). **DOT is now ◑** — it recently
  shipped both 9728 (protected-resource metadata) and 8707 (resource indicators) alongside its
  existing 8414 metadata, PKCE, and DCR, so it can act as an MCP resource server; only a named
  OAuth 2.1 posture is still missing.

## The one-line story for DOT

DOT is **strong on OAuth 2.0 and OIDC** (the two suites most projects actually need), **near
on OAuth 2.1** (defaults already aligned — closing it is mostly a config-profile question),
**partway on MCP** (it just added the 9728 + 8707 resource-server pieces; a named OAuth 2.1
posture is the remaining gap), and **absent on FAPI 2.0** (which needs sender-constrained
tokens and PAR). That's a coherent, defensible position for a general-purpose Django
provider — and it makes the roadmap obvious: an OAuth-2.1 mode is low-hanging; FAPI is the
larger investment.
