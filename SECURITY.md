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

If you cannot use GitHub, email **security@cboxdk.com** with the details. Encrypt
sensitive reports if possible; our key is published at
`https://cboxdk.com/.well-known/security.txt` (RFC 9116).

Please include:

- the affected version / commit and component (e.g. OAuth token endpoint, SAML ACS),
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested remediation.

## Our commitment (response targets)

| Stage | Target |
|-------|--------|
| Acknowledge receipt | within **2 business days** |
| Initial assessment & severity | within **5 business days** |
| Fix or mitigation for High/Critical | within **30 days** of confirmation |
| Coordinated public disclosure | by mutual agreement, default **90 days** |

We will keep you informed throughout, credit you in the advisory and `CHANGELOG.md`
(unless you prefer to remain anonymous), and request a CVE for confirmed
vulnerabilities through GitHub's CNA.

## Safe harbor

We will not pursue or support legal action against anyone who, in good faith:

- reports a vulnerability through the private channel above,
- avoids privacy violations, data destruction, and service degradation,
- only interacts with accounts they own or have explicit permission to test, and
- gives us reasonable time to remediate before public disclosure.

Good-faith security research conducted under this policy is authorized. If in doubt
about whether an action is in scope, ask first at security@cboxdk.com.

## Supported versions

Security fixes are provided for the latest minor release. During the pre-1.0
period, only the latest tagged release is supported.

| Version | Supported |
|---------|-----------|
| latest `0.x` | ✅ |
| older `0.x` | ❌ |

## What we do to keep this safe

The engineering posture is documented in [`docs/security.md`](docs/security.md) and
the RFC/standard conformance in [`docs/standards.md`](docs/standards.md). In short:

- **Deny-by-default tenant isolation**, verified by tests.
- **All crypto through one kernel** — explicit JWT algorithm allow-list (no `alg`
  confusion, per RFC 8725), XChaCha20-Poly1305 AEAD for secrets at rest, key
  rotation with `kid` overlap.
- **Tamper-evident, hash-chained audit log** with signed checkpoints.
- **CI gates on every push**: PHPStan (max), Pest, `composer audit`, license
  compliance, a CycloneDX SBOM freshness check, secret scanning, and SAST.
- **A published conformance matrix** mapping the code to the RFCs and to OWASP ASVS.

## Disclosure history

Confirmed vulnerabilities and their fixes are published as
[GitHub Security Advisories](https://github.com/cboxdk/laravel-id/security/advisories)
and noted under **Security** in [`CHANGELOG.md`](CHANGELOG.md).
