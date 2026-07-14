---
title: Threat model
description: STRIDE analysis of the identity platform and its mitigations
weight: 10
---

# Threat model

A STRIDE pass over the platform's trust boundaries — structured the way an ISO 27001,
SOC 2, or OWASP ASVS reviewer approaches one, and the map we hold new features against.
It is an engineering artifact, not a certification or audit result.

## Assets & trust boundaries

- **Assets:** user credentials & MFA secrets, signing keys, session tokens, OAuth
  client secrets, the audit trail, tenant data isolation.
- **Boundaries:** browser ↔ app, app ↔ OAuth/OIDC clients, app ↔ upstream IdP
  (SAML/OIDC), app ↔ directory (SCIM), app ↔ webhook receivers, app ↔ database, and
  tenant ↔ tenant.

## STRIDE

### Spoofing (authenticity)

| Threat | Mitigation |
|--------|-----------|
| Credential theft / stuffing | MFA (TOTP replay-safe, passkeys UV-enforced), rate limits (breached-password screen is an app-layer add-on) |
| `alg=none` / algorithm confusion | explicit alg allow-list, per-key alg binding (RFC 8725) |
| Forged SAML/OIDC assertions | XML-DSig / JWS verification, RS256-pinned, `iss`/`aud` checks, replay guard |
| Session fixation | session id regenerated on login |
| Token-type confusion | `typ: at+jwt` on access tokens (RFC 9068) |

### Tampering (integrity)

| Threat | Mitigation |
|--------|-----------|
| Audit-log alteration | hash-chained entries; signed checkpoints detect edits/reorder/truncation |
| Token payload tampering | JWT signature verification |
| Webhook replay/alteration | HMAC over `timestamp.body`, receiver tolerance window |
| Mass-assignment | writes flow through value objects, not raw request input |

### Repudiation (accountability)

| Threat | Mitigation |
|--------|-----------|
| "I didn't do that" | tamper-evident audit trail of auth, provisioning, key, and admin events |
| Untracked key use | every token records a `jti`; keys carry a `kid` |

### Information disclosure (confidentiality)

| Threat | Mitigation |
|--------|-----------|
| Secrets at rest | XChaCha20-Poly1305 AEAD, context-bound; secrets never logged |
| Cross-tenant data leak | deny-by-default tenant scope; missing tenant ⇒ zero rows |
| SSRF to internal services / metadata | `cboxdk/laravel-ssrf` guard on outbound URLs |
| Email/account enumeration | constant-time login timing, generic errors |
| Token leakage window | short (15 min) access-token TTL; revocation; refresh rotation |

### Denial of service (availability)

| Threat | Mitigation |
|--------|-----------|
| Brute force / automated abuse | per-endpoint rate limits, login/MFA/signup throttles |
| Algorithmic-complexity DoS (auth graph) | visited-set cycle guard in relationship checks |
| Flooded webhook retries | bounded retry schedule |

### Elevation of privilege (authorization)

| Threat | Mitigation |
|--------|-----------|
| Horizontal (IDOR) | org-scoped queries on connection/role/invitation operations |
| Vertical (role escalation) | owner-only guards; org-membership check on org switch |
| Sensitive action on a stolen session | step-up "sudo" re-authentication (RFC 9470 analogue) |
| Privileged token minting | confidential-client secret required on auth_code; introspection auth |

## Residual risk (honest scope)

- **Audit is tamper-evident, not tamper-proof** — anchor checkpoints externally.
- **Risk-scoring is an app-layer add-on, not shipped by this package.** The host app
  can add bot/abuse scoring on top (e.g. `cboxdk/laravel-risk`) to feed CAPTCHA /
  step-up / reject decisions; this framework provides the rate limits, throttles and
  MFA it composes with.
- **App-layer SSRF is defense in depth** — a network egress allow-list is the
  complete fix.
- **Revocation is effective at the introspection endpoint**; resource servers that
  verify JWTs locally rely on the short TTL.
- **A determined human with clean signals** defeats heuristic abuse scoring — it
  raises cost, it isn't a wall.
- **The crypto master key's custody** (KMS/HSM/backup) is the operator's to secure.
