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
| SSRF to internal services / metadata | `cboxdk/laravel-ssrf` guard on outbound URLs — including the client ID metadata document (and its `jwks_uri`) a client names in `client_id`: resolved and pinned, https only, no redirects, size- and time-limited, and checked against the client-ID URL shape before any request is made |
| Email/account enumeration | constant-time login timing, generic errors |
| Token leakage window | short (15 min) access-token TTL; revocation; refresh rotation |

### Denial of service (availability)

| Threat | Mitigation |
|--------|-----------|
| Brute force / automated abuse | per-endpoint rate limits, login/MFA/signup throttles |
| Algorithmic-complexity DoS (auth graph) | visited-set cycle guard in relationship checks |
| Flooded webhook retries | bounded retry schedule |
| Registration flooding (open / `mcp` DCR) | per-minute throttle plus a per-address hourly ceiling; unused self-registered clients swept by `cbox-id:prune` when enabled |

### Elevation of privilege (authorization)

| Threat | Mitigation |
|--------|-----------|
| Horizontal (IDOR) | org-scoped queries on connection/role/invitation operations |
| Vertical (role escalation) | owner-only guards; org-membership check on org switch |
| Sensitive action on a stolen session | short absolute + idle session lifetimes, and MFA verification primitives. Access tokens carry `auth_time` and `acr` (derived from `amr`, reserved against hooks), and `AuthenticationRequirement` gives both ends of RFC 9470 step-up: a resource server checks a token and returns the `insufficient_user_authentication` challenge; `/authorize` reads `acr_values`/`max_age` and assesses the session. **Wiring them in is the app's**: the package ships no sudo mode for its own console and no route middleware |
| Privileged token minting | confidential-client secret required on auth_code; introspection auth |
| Self-registered client minting a token for someone else's resource server (confused deputy) | a self-registered client (RFC 7591, or a metadata document) may be audienced only to a registered API, a declared resource open to such clients, or the issuer; a repeated `resource` is refused so no token is valid at two resource servers; a refresh token never changes audience; reserved scopes are never granted to such a client |

## Residual risk (honest scope)

- **Audit is tamper-evident, not tamper-proof** — anchor checkpoints externally. Note
  that checkpointing is **available but not scheduled by default**:
  `cbox-id:audit:checkpoint` signs every chain and can be scheduled with
  `audit.checkpoint.schedule`, but that flag ships `false` (the first signature
  forecloses a planned one-time re-chain — see UPGRADING.md). Until you enable it or
  call for a checkpoint yourself, deletion of a chain's *tail* is not detectable at all.
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
  Rotating it is supported (a versioned keyring plus `cbox-id:crypto:rewrap`, see
  [master key management](key-management.md)), but rotation does not undo a
  compromise: rotate the secrets it sealed too.
- **The front-channel is the host's attack surface.** This package does not serve
  `/authorize`; consent, `prompt`/`max_age`/`acr_values` handling, registered-set
  redirect matching and the RFC 9207 `iss` parameter are threats your app owns. See
  the boundary note in [Standards & conformance](standards.md).
