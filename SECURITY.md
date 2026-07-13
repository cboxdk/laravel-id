# Security Policy

Cbox ID is security infrastructure — a vulnerability here can expose every user of
every deployment at once. We treat security as the product. This document explains
how to report a vulnerability, what to expect from us, and the standards we hold
the code to.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through **GitHub Private Vulnerability Reporting**:
[Report a vulnerability](https://github.com/cboxdk/laravel-id/security/advisories/new)
(repository → **Security** → **Report a vulnerability**).

Please include:

- the affected version / commit and component (e.g. OAuth token endpoint, SAML ACS),
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested remediation.

## What to expect

This is a pre-1.0, open-source project maintained on a best-effort basis. We will
respond as promptly as we can, keep you informed while we investigate, and (unless
you prefer to stay anonymous) credit you when a fix ships. We coordinate the timing
of any public disclosure with you.

## Safe harbor

We will not pursue or support legal action against anyone who, in good faith:

- reports a vulnerability through the private channel above,
- avoids privacy violations, data destruction, and service degradation,
- only interacts with accounts they own or have explicit permission to test, and
- gives us reasonable time to remediate before public disclosure.

Good-faith security research conducted under this policy is authorized. If in doubt
about whether an action is in scope, ask first through the private reporting channel
above.

## Supported versions

Security fixes are provided for the latest minor release. During the pre-1.0
period, only the latest tagged release is supported.

| Version | Supported |
|---------|-----------|
| latest `0.x` | ✅ |
| older `0.x` | ❌ |

## What we do to keep this safe

The engineering posture is documented in [`docs/security.md`](docs/security/_index.md) and
the RFC/standard conformance in [`docs/standards.md`](docs/security/standards.md). In short:

- **Deny-by-default tenant isolation**, verified by tests.
- **All crypto through one kernel** — explicit JWT algorithm allow-list (no `alg`
  confusion, per RFC 8725), XChaCha20-Poly1305 AEAD for secrets at rest, key
  rotation with `kid` overlap.
- **Tamper-evident, hash-chained audit log** with signed checkpoints.
- **CI gates on every push**: PHPStan (max), Pest, `composer audit`, license
  compliance, a CycloneDX SBOM freshness check, secret scanning, and SAST.
- **A published conformance matrix** ([`docs/standards.md`](docs/security/standards.md))
  mapping the code to the RFCs and specs it implements.

## Disclosure history

Confirmed vulnerabilities and their fixes are published as
[GitHub Security Advisories](https://github.com/cboxdk/laravel-id/security/advisories)
and noted under **Security** in [`CHANGELOG.md`](CHANGELOG.md).
