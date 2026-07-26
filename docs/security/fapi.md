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

## What the baseline requires — and where Cbox ID stands

| FAPI 2.0 baseline requirement | Cbox ID |
|---|---|
| **Authorization Code + PKCE (`S256`)**, no implicit/hybrid | ✅ always — `code` only, PKCE mandatory, `plain` refused |
| **PAR** — request parameters pushed back-channel (RFC 9126) | ✅ `/oauth/par`; **enforced** when `require_par` is on |
| **Sender-constrained access tokens** (DPoP or mTLS) | ◐ DPoP (RFC 9449) implemented — `cnf.jkt`, replay-guarded proofs — but **not enforced server-side**; mTLS (RFC 8705) is not implemented |
| **Exact `redirect_uri` matching** | ✅ always — only URIs the client registered, compared exactly |
| **`iss` in the authorization response** (RFC 9207, mix-up defense) | ✅ always on |
| **Signing algorithm** — FAPI 2.0 permits only `PS256`, `ES256`, `EdDSA` | ❌ tokens are signed **`RS256`**, which the profile does not permit; `PS256` is not implemented |
| **No `alg: none`, no symmetric (HS\*)** | ✅ closed alg set (RS256 / ES256 / EdDSA), per-key alg binding |
| **Short-lived, revocable tokens** | ✅ 15-min access tokens, `jti`-tracked, `/oauth/revoke`, refresh rotation + reuse detection |
| **Confidential clients authenticated** | ✅ `private_key_jwt` (RFC 7523) or a secret verified in constant time (public clients rely on PKCE) |

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

Neither gap weakens the controls that *are* in place — PAR, PKCE, exact redirect
matching, `iss`, rotation-with-reuse-detection and DPoP-when-presented all behave as
described above. What they mean is that the FAPI 2.0 profile itself cannot honestly
be claimed as met, so plan for both if a certification audit is in scope.

## What you can turn on today

The one switch that changes behavior is **mandatory PAR**:

```dotenv
CBOX_ID_REQUIRE_PAR=true
```

With it set:

- `/authorize` **refuses** any request that didn't come through `/oauth/par` — no
  authorization parameters can travel on the browser URL, where they could be
  logged, tampered with, or leaked via the Referer header.
- The metadata advertises `require_pushed_authorization_requests: true`, so
  conformant clients switch to PAR automatically.

Mandatory PAR is the one server-side switch the profile calls for that Cbox ID can
flip today; the ✅ rows above are on by default and need no configuration. Because
the server cannot yet *require* DPoP, pair this with a client fleet that always
sends DPoP proofs and a resource server that rejects a token without a `cnf` claim.

## The flow, end to end

```
1. Client → POST /oauth/par        (authenticated; params + PKCE + DPoP key)
             ← { request_uri, expires_in }
2. Browser → GET /authorize?client_id=…&request_uri=urn:ietf:…   (nothing else)
             user authenticates + consents
             ← redirect  ?code=…&iss=https://id.acme.com&state=…
3. Client → POST /oauth/token      (code + PKCE verifier + DPoP proof)
             ← DPoP-bound access token (token_type: DPoP, cnf.jkt)
```

Each step closes an attack class: PAR keeps parameters off the URL, `iss` defeats
IdP mix-up, PKCE binds the code to the client, and DPoP binds the token to a key a
stolen bearer doesn't have.

## Where to go next

- [Standards & conformance](standards.md) — the RFC-by-RFC matrix.
- [Security](_index.md) — the crypto and isolation invariants underneath.
- [Threat model](threat-model.md) — the STRIDE analysis these controls map to.
