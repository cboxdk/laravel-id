---
title: Security
description: The non-negotiable invariants — tenant isolation, crypto, tamper-evident audit
weight: 7
---

# Security

An identity platform is crown-jewels infrastructure: one breach exposes every customer at once.
Security is treated as the product, not a layer on top. The reporting policy and CI gates
live in `SECURITY.md` and the STRIDE analysis in [`threat-model.md`](threat-model.md); the
load-bearing invariants are here. The design draws on OWASP ASVS as a reference checklist —
not an audited or certified conformance claim.

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
- **Streaming the trail to a customer's SIEM** is environment-isolated and carries the
  chain metadata for dedup and gap-detection at the destination — with two operator-only
  safety toggles that must never reach a tenant. See
  [Audit streaming — isolation & operator-only controls](audit-streaming.md).

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

## Outbound provisioning

Pushing users OUT to downstream apps is authenticated, server-side egress carrying
tenant data. Its controls mirror the other egress paths: SSRF-guarded and IP-pinned
requests (base URL and OAuth token URL), TLS-verify on, connection secrets sealed
at rest and never logged or dead-lettered, environment-owned deny-by-default scope,
and bounded retries with a per-connection circuit breaker. Delivery is honestly
**at-least-once**, not exactly-once. See
[Outbound provisioning security](provisioning.md).

## One-time passcodes (OTP)

Delivered email/SMS codes are an auth factor, so their controls are load-bearing.
A short code is safe because of the **caps**, not its entropy: it is stored only as
a **keyed HMAC** (never plaintext), single-use, TTL-bounded, attempt-capped, and
rate-limited on both issue (anti-bomb / anti-SMS-cost) and verify (anti-brute-force).
Verification is constant-time on every path — including the miss — and returns a
uniform result, so there is no enumeration or timing oracle. Honest scope: SMS is
only as secure as SIM-swap resistance; prefer a phishing-resistant primary factor.
See [Security: OTP](otp.md).

## AI token vault

The vault holds downstream third-party credentials that carry real power, so its
value is stored **sealed** (SecretBox, recoverable — the vault must replay it, so
hashing won't do), never plaintext. Access is deny-by-default: a lease needs a live
`(secret, client)` grant, and every failure raises a **uniform** `LeaseDenied` (the
reason audited, never returned) so the vault is no enumeration oracle. Every store,
rotation, revocation, grant and lease is audited with actor and purpose — never the
value. Honest scope: a lease TTL is advisory, and master-key rotation is a manual
re-seal. See [Security: token vault](token-vault.md).

## CIBA backchannel approval

CIBA issues tokens on an out-of-band human approval, so it inherits the device
grant's hardening: a CSPRNG `auth_req_id` stored only as a hash, single-use under a
row lock, TTL-bounded, and poll-throttled (`slow_down`). The client's polling secret
and the host's internal approval handle are **separate identifiers**, so a client
can never approve its own request. Poll mode only; the approval channel's strength
is the host's. See [Security: CIBA](ciba.md).

## Access governance

Identity governance makes over-provisioned access visible and removable, so its own
controls are load-bearing. Certification campaigns **apply** revokes against the real
access contracts (not paper decisions), items left un-reviewed at close default to
**revoke** (deny-by-default), and a revoke the domain refuses — removing an org's last
owner — is recorded and audited (`governance.access.revoke_blocked`), never silently
dropped. Segregation-of-Duties returns a reasoned `Decision` before a grant completes a
toxic combination. Everything is environment-isolated and correlated on the audit trail
by `campaign_id`. See [Security: access governance](governance.md).

## Reporting

Found a vulnerability? See `SECURITY.md` for private disclosure and safe-harbor terms. Do not
open a public issue.
