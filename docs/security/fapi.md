---
title: FAPI hardening
description: The FAPI 2.0 building blocks Cbox ID ships, and the profile requirements it does not yet meet
weight: 9
---

# FAPI hardening

FAPI (the Financial-grade API security profile) is what regulators and high-value
APIs — open banking, health, payments — require on top of plain OAuth/OIDC. Cbox ID
ships the **building blocks a FAPI 2.0 deployment is assembled from** — PAR, DPoP,
`private_key_jwt`, PKCE `S256`, exact redirect matching and `iss` — so a deployment
that needs the profile starts from hardened defaults instead of a re-architecture.

Cbox ID is **not a certified FAPI 2.0 implementation**, and two of the profile's
`SHALL` requirements are not met today. If you are scoping a regulated deployment,
read [What is not met yet](#what-is-not-met-yet) first — the table below is the
honest per-requirement status, not a conformance claim.

> **Half of this profile lives at `/authorize`, which this package does not serve.**
> Several FAPI requirements are decided at the authorization request — refusing a
> non-PAR request, matching `redirect_uri` against the registered set, appending
> RFC 9207 `iss`. This package ships the back-channel those depend on; your
> application (or the deployable cbox-id app) has to enforce them. Rows marked
> **your app** below are exactly those. Deploying this package alone and setting the
> switches does **not** give you the profile.

## What the baseline requires — and where Cbox ID stands

| FAPI 2.0 baseline requirement | This package |
|---|---|
| **Authorization Code + PKCE (`S256`)**, no implicit/hybrid | ✅ `code` only; `S256` only, and `plain` cannot be redeemed. Public-client PKCE is enforced on `/oauth/par`; at `/authorize` it is **your app's** — though a code minted without a challenge can never be exchanged, so a mistake fails closed |
| **PAR** — request parameters pushed back-channel (RFC 9126) | ◐ `/oauth/par` issues a client-authenticated, single-use, 90-second `request_uri` and `consume()` is available. **Consumption and refusal happen at `/authorize` — your app.** `CBOX_ID_REQUIRE_PAR=true` sets the discovery flag and nothing else |
| **Sender-constrained access tokens** (DPoP or mTLS) | ◐ DPoP (RFC 9449) implemented — `cnf.jkt`, replay-guarded proofs — but **not enforced server-side** (no `require_dpop`, no per-client flag); mTLS (RFC 8705) is not implemented |
| **Exact `redirect_uri` matching** | ◐ The token exchange compares the presented URI to the one recorded on the code, in constant time. Matching against the client's **registered** set happens at `/authorize` — **your app** |
| **`iss` in the authorization response** (RFC 9207, mix-up defense) | ◐ **Your app.** This package emits no authorization response. It *advertises* `authorization_response_iss_parameter_supported` as soon as you configure an `authorization_endpoint` — so if your `/authorize` does not append `iss`, that advertisement is false to mix-up-hardened clients |
| **Signing algorithm** — FAPI 2.0 permits only `PS256`, `ES256`, `EdDSA` | ❌ tokens are signed **`RS256`**, which the profile does not permit; `PS256` is not implemented |
| **No `alg: none`, no symmetric (HS\*)** | ✅ closed alg set (RS256 / ES256 / EdDSA), per-key alg binding |
| **Short-lived, revocable tokens** | ✅ 15-min access tokens, `jti`-tracked, `/oauth/revoke`, refresh rotation + reuse detection |
| **Confidential clients authenticated** | ✅ `private_key_jwt` (RFC 7523 §3) or a secret verified in constant time (public clients rely on PKCE). Note a **dynamically registered** client cannot select `private_key_jwt` |

## What is not met yet

Two gaps stand between the current implementation and the FAPI 2.0 baseline. Both
are structural, not configuration — no environment variable closes them today.

**1. Token signing is `RS256`.** FAPI 2.0 Final permits only `PS256`, `ES256` or
`EdDSA`; `RS256` (RSASSA-PKCS1-v1_5) is excluded. The crypto kernel supports
`ES256` and `EdDSA` keys, but access tokens and `id_token`s are signed `RS256`
(`JwtTokenSigner` defaults to it and `TokenController` pins the `id_token` to it),
and `PS256` (RSASSA-PSS) is not implemented at all. A conforming deployment needs
`PS256` support plus a signing algorithm that is selectable per environment.

**2. Sender-constraining is opt-in, not required.** FAPI 2.0 requires the
authorization server to issue **only** sender-constrained access tokens. Cbox ID
implements DPoP correctly and binds `cnf.jkt` whenever a client presents a proof —
but there is no `require_dpop` switch. A client that simply omits the `DPoP` header
receives an ordinary Bearer token, so the constraint is a client-side choice rather
than a server-enforced invariant. Until that switch exists, sender-constraining must
be enforced outside the authorization server (for example at the resource server, by
refusing tokens without a `cnf` claim).

**3. The front-channel requirements are not this package's to meet.** Mandatory PAR,
registered-set redirect matching and RFC 9207 `iss` all happen at `/authorize`. They are
listed here because the profile requires them, not because installing this package
delivers them.

None of these gaps weakens the controls that *are* in place — the PAR issuer, PKCE
verification, constant-time redirect comparison, rotation-with-reuse-detection and
DPoP-when-presented all behave as described. What they mean is that the FAPI 2.0 profile
cannot honestly be claimed as met, so plan for all three if a certification audit is in
scope.

## What you can turn on today

```dotenv
CBOX_ID_REQUIRE_PAR=true
```

Be precise about what this does and does not do:

- It advertises `require_pushed_authorization_requests: true`, so conformant clients
  switch to PAR automatically.
- It does **not** refuse anything. This package reads that config key in exactly one
  place — building the discovery document. The refusal of a non-PAR authorization
  request must be implemented by whatever serves `/authorize`, by calling
  `PushedAuthorizationRequests::consume()` and rejecting a request that carries no
  `request_uri`. The deployable cbox-id app does this; a hand-rolled `/authorize` must.

The ✅ rows above are on by default and need no configuration. Because the server cannot
*require* DPoP, pair this with a client fleet that always sends DPoP proofs and a resource
server that rejects a token without a `cnf` claim.

## The flow, end to end

```
1. Client → POST /oauth/par        (authenticated; params + PKCE + DPoP key)
             ← { request_uri, expires_in }
2. Browser → GET /authorize?client_id=…&request_uri=urn:ietf:…   (nothing else)
             user authenticates + consents          ← YOUR APP, not this package
             ← redirect  ?code=…&iss=https://id.acme.com&state=…
3. Client → POST /oauth/token      (code + PKCE verifier + DPoP proof)
             ← DPoP-bound access token (token_type: DPoP, cnf.jkt)
```

Each step closes an attack class: PAR keeps parameters off the URL, `iss` defeats
IdP mix-up, PKCE binds the code to the client, and DPoP binds the token to a key a
stolen bearer doesn't have. Steps 1 and 3 are this package; step 2 is yours.

## Where to go next

- [Standards & conformance](standards.md) — the RFC-by-RFC matrix.
- [Security](_index.md) — the crypto and isolation invariants underneath.
- [Threat model](threat-model.md) — the STRIDE analysis these controls map to.
