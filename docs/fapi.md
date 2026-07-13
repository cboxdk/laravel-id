---
title: FAPI hardening
description: The FAPI 2.0-aligned baseline Cbox ID can enforce for high-assurance (open-banking-grade) clients
weight: 9
---

# FAPI hardening

FAPI (the Financial-grade API security profile) is what regulators and high-value
APIs — open banking, health, payments — require on top of plain OAuth/OIDC. Cbox ID
ships the building blocks and can **enforce** the FAPI 2.0 baseline, so a deployment
that needs it can turn it on rather than re-architect.

## What the baseline requires — and where Cbox ID stands

| FAPI 2.0 baseline requirement | Cbox ID |
|---|---|
| **Authorization Code + PKCE (`S256`)**, no implicit/hybrid | ✅ always — `code` only, PKCE mandatory, `plain` refused |
| **PAR** — request parameters pushed back-channel (RFC 9126) | ✅ `/oauth/par`; **enforced** when `require_par` is on |
| **Sender-constrained access tokens** (DPoP or mTLS) | ✅ DPoP (RFC 9449) — `cnf.jkt`, replay-guarded proofs |
| **Exact `redirect_uri` matching** | ✅ always — only URIs the client registered, compared exactly |
| **`iss` in the authorization response** (RFC 9207, mix-up defense) | ✅ always on |
| **Strong signing** — no `alg: none`, no HS* | ✅ closed alg set: RS256 / ES256 / EdDSA |
| **Short-lived, revocable tokens** | ✅ 15-min access tokens, `jti`-tracked, `/oauth/revoke`, refresh rotation + reuse detection |
| **Confidential clients authenticated** | ✅ secret verified in constant time (public clients rely on PKCE) |

## Turning it on

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

Everything else in the table is on by default — FAPI mode simply removes the
non-PAR escape hatch and pairs naturally with requiring DPoP on your clients.

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
- [Security](security.md) — the crypto and isolation invariants underneath.
- [Threat model](threat-model.md) — the STRIDE analysis these controls map to.
