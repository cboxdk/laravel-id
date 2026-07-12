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

Assertion validation is isolated behind `AssertionValidator` and dispatched per connection
type. A type with no registered validator is **rejected**, never trusted.

- **OIDC** — the `id_token` (a JWS) is verified via `firebase/php-jwt` with the verification
  key **pinned to RS256**, closing algorithm-confusion / `alg: none`. `exp`/`nbf` are enforced;
  `iss` and `aud` are asserted in constant time.
- **SAML** — the Response is validated by `onelogin/php-saml` (XML-DSig signature verification,
  XSW defense, XML parsed with external entities disabled for XXE). On top of it we run strict
  mode with `wantAssertionsSigned`, so an unsigned assertion is refused.
- **WebAuthn / passkeys** — registration and assertion signatures are verified with **OpenSSL**
  (ES256/P-256 and RS256); COSE/CBOR is decoded by the vetted `spomky-labs/cbor-php`. Challenge,
  origin, RP-id hash and user-presence are all enforced, and the sign-count guard flags cloned
  authenticators. No hand-rolled cryptography anywhere.

## Supply chain: licenses & SBOM

- **Own the code.** Security-critical logic lives in this package; third-party libraries are
  used only for well-trodden primitives (JWT, XML-DSig, CBOR, sodium) — each vetted and pinned.
- `composer license-check` fails the build if any dependency is not offered under a permissive
  license (MIT/BSD/Apache/ISC and friends). Dual-licensed packages pass on their permissive
  option; genuine exceptions are listed with a reason in `bin/check-licenses.php`.
- `composer sbom` produces a deterministic **CycloneDX 1.5** SBOM (`sbom.json`) straight from
  `composer.lock`. CI regenerates it and fails if the committed copy is stale, so the SBOM
  never drifts from what actually ships.
- `composer audit` (also in CI, `--no-dev`) blocks known-vulnerable dependencies.

## Offboarding

- SCIM deprovision / deactivation drops membership **and revokes the user's sessions
  immediately** — access ends the moment the directory says so, not at token expiry.

## Reporting

Found a vulnerability? See `SECURITY.md` for private disclosure and safe-harbor terms. Do not
open a public issue.
