---
title: Security
description: The non-negotiable invariants — tenant isolation, crypto, tamper-evident audit
weight: 7
---

# Security

An identity platform is crown-jewels infrastructure: one breach exposes every customer at once.
Security is treated as the product, not a layer on top. The full posture (threat model, CI
gates, OWASP ASVS L3 target) lives in `SECURITY.md`; the load-bearing invariants are here.

## Tenant isolation (deny-by-default)

- Every tenant-owned model uses `BelongsToTenant` and is filtered by the global tenant scope.
- **No tenant in context ⇒ zero rows.** A missing tenant never returns another tenant's data.
- Writes are guarded: you cannot persist a row for a tenant other than the one you act as.
- Cross-tenant reach is explicit and audited — `runAs()` (act as one tenant), `scopedTo()`
  (bounded, authorized roll-up set), `withoutScope()` (kernel-only escape hatch).

## Cryptography

- All JWT signing/verification and encryption go through the Crypto kernel.
- **`verify()` takes an explicit algorithm allow-list** — the algorithm is never trusted from
  the token header, which defeats `alg=none` and RS↔HS confusion.
- Secrets (connection config, MFA secrets, private signing keys, webhook secrets) are sealed
  at rest with AEAD envelope encryption bound to a context, and are never logged.
- Signing keys rotate with a `kid` and an overlap window so in-flight tokens keep verifying.

## Tamper-evident audit

- The trail is append-only and hash-chained: `hash = SHA256(canonical(entry) ‖ prev_hash)`.
- `verifyChain()` detects content tampering, reordering and deletion.
- Honest scope: this is tamper-**evident**, not tamper-**proof**. `checkpoint()` signs the
  chain head so you can anchor it to an external, append-only store — that's what makes it
  tamper-resistant against someone who can rewrite the database.
- The chain proves *integrity*, not *completeness*. Logging coverage of security-relevant
  actions is a separate obligation.

## Federation

- SAML/OIDC assertion validation is isolated behind `AssertionValidator` and MUST wrap a
  vetted library: verify signatures, reject unsigned/tampered/expired/mis-audienced assertions,
  parse XML with external entities disabled (XXE), and guard against signature wrapping (XSW).

## Offboarding

- SCIM deprovision / deactivation drops membership **and revokes the user's sessions
  immediately** — access ends the moment the directory says so, not at token expiry.

## Reporting

Found a vulnerability? See `SECURITY.md` for private disclosure and safe-harbor terms. Do not
open a public issue.
