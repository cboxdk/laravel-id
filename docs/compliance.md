---
title: Compliance mapping
description: How the platform's controls map to SOC 2, ISO 27001, NIS2, GDPR, HIPAA, and PCI-DSS
weight: 9
---

# Compliance mapping

## Read this first — what a library can and can't do

**No software package is "SOC 2 certified" or "ISO 27001 certified."** Those
certify an *organization's* management system and a *service's* operation — people,
process, and evidence over time — not source code. HIPAA and PCI-DSS likewise apply
to *entities* handling PHI or cardholder data, not to a dependency.

What Cbox ID does is provide the **technical controls** those frameworks require,
implemented correctly and testably, plus the **evidence artifacts** (audit logs, an
SBOM, a conformance matrix, a threat model) an auditor asks for. It moves a large
part of the control burden off your plate — but you, the operator, still own the
organizational controls (policies, training, vendor management, retention
schedules, incident response, a DPIA, and an actual audit).

So the honest framing: **adopting Cbox ID puts the identity-and-access,
cryptography, and audit-logging controls of these frameworks "in scope and
satisfied" at the technical layer.** The tables below map each framework's relevant
requirements to the feature that addresses it, and end with what remains yours.

## SOC 2 (Trust Services Criteria)

| TSC | Requirement | Cbox ID control |
|-----|-------------|-----------------|
| CC6.1 | Logical access controls | RBAC, relationship/entitlement authorization, deny-by-default tenant isolation |
| CC6.1 | Encryption of credentials/keys at rest | XChaCha20-Poly1305 AEAD for all secrets; signing keys sealed |
| CC6.2 | Registration & authorization of users | Explicit provisioning, SCIM, invitation flow; no silent account merge |
| CC6.3 | Least privilege / role changes | Roles + permissions, org-scoped, cross-tenant write guard |
| CC6.6 | Authentication (MFA) | Passwords (breach-screened), TOTP (replay-safe), WebAuthn/passkeys (UV-enforced), step-up |
| CC6.7 | Transmission protection | Bearer over TLS; HSTS; SSRF-guarded webhooks; SAML/OIDC signature verification |
| CC6.8 | Prevent unauthorized software | SBOM, dependency audit, license gate in CI |
| CC7.1–7.2 | Monitoring / anomaly detection | Hash-chained audit log (framework); request risk-scoring is an **app-layer add-on** (e.g. `cboxdk/laravel-risk`, shipped by the host app — not this package) |
| CC7.2 | Security event logging | Audit trail of auth, provisioning, key, and admin events |
| CC8.1 | Change management | Signed commits, CI gates, conventional commits, CHANGELOG |

## ISO/IEC 27001:2022 (Annex A controls)

| Annex A | Control | Cbox ID |
|---------|---------|---------|
| A.5.15–5.18 | Access control, identity, authentication | RBAC, provisioning, MFA, session management |
| A.8.2 / A.8.3 | Privileged & information access rights | Owner/admin roles, step-up ("sudo") re-auth, org scoping |
| A.8.5 | Secure authentication | Passkeys (phishing-resistant), TOTP, breach-screened passwords |
| A.8.24 | Use of cryptography | Crypto kernel: alg allow-list (RFC 8725), AEAD at rest, key rotation |
| A.8.15 | Logging | Tamper-evident, hash-chained audit log with signed checkpoints |
| A.8.16 | Monitoring activities | Auditable security events (framework); risk-scoring pipeline at the app layer (add-on) |
| A.5.23 | Cloud service security | Self-hostable; no data leaves your infrastructure |
| A.8.8 | Management of technical vulnerabilities | `composer audit`, Dependabot, SAST, SBOM in CI |
| A.8.28 | Secure coding | PHPStan max, Pint, tests against real vectors, honest-crypto stance |

## NIS2 Directive (Art. 21 measures)

| Art. 21(2) measure | Cbox ID |
|--------------------|---------|
| (a) risk analysis & security policies | threat model + this mapping give the technical basis |
| (d) supply-chain security | SBOM (CycloneDX), pinned deps, license + vuln gates |
| (g) basic cyber hygiene / access control | MFA, RBAC, least privilege, step-up |
| (h) cryptography | Crypto kernel, key rotation, sealed secrets |
| (i) HR security / access control | provisioning + immediate deprovision (SCIM revokes sessions) |
| (j) MFA & secured comms | passkeys/TOTP; signed/verified federation; HSTS |
| incident handling / reporting | audit trail + security event log as forensic evidence |

## GDPR (data protection by design)

| Article | Requirement | Cbox ID |
|---------|-------------|---------|
| Art. 25 | Data protection by design & default | deny-by-default tenancy, minimal token claims, self-hosted |
| Art. 32 | Security of processing | AEAD at rest, MFA, alg allow-list, audit log, SSRF/rate-limit defenses |
| Art. 30 | Records of processing | audit trail of identity/access events |
| Art. 33 | Breach detection & notification | tamper-evident log surfaces anomalies for your 72h clock (plus app-layer risk-scoring, if added) |
| Art. 22 | Automated decisions | **applies at the app layer, not this framework** — if the host adds risk-scoring (e.g. `cboxdk/laravel-risk`) it is explainable (reasons breakdown) and ships in monitor mode; see that package's docs |
| Art. 17 | Right to erasure | opaque subject model — the platform holds no PII it can't delete via your resolver |

## HIPAA Security Rule (§164.312 technical safeguards)

| Safeguard | Cbox ID |
|-----------|---------|
| §164.312(a)(1) Access control | RBAC, unique user identity, tenant isolation |
| §164.312(a)(2)(i) Unique user ID | opaque per-subject id |
| §164.312(a)(2)(iii) Automatic logoff | absolute + idle session timeout |
| §164.312(b) Audit controls | hash-chained audit log |
| §164.312(c) Integrity | signed checkpoints detect tampering; JWT signature verification |
| §164.312(d) Person/entity authentication | MFA, passkeys, breach-screened passwords |
| §164.312(e) Transmission security | TLS bearer, HSTS, signed federation assertions |

## PCI-DSS v4.0 (relevant requirements)

| Requirement | Cbox ID |
|-------------|---------|
| Req 3/4 — protect & encrypt data | AEAD-sealed secrets; TLS transmission; no secret ever logged |
| Req 6 — secure development | CI gates, SAST, dependency scanning, SBOM |
| Req 7 — restrict access by need-to-know | RBAC, least privilege, deny-by-default |
| Req 8 — identify & authenticate | unique IDs, **MFA (8.4)**, strong password + breach screen (8.3), session mgmt |
| Req 8.3.6 | password length/complexity | 12-char minimum, NIST-aligned, HIBP screen |
| Req 10 — log & monitor | tamper-evident audit log of all access to auth systems |
| Req 11 — test security | tests vs real vectors; pen-test cadence is the operator's to schedule |

## What remains yours (the organizational controls)

The package cannot supply these — they are process, not code:

- **Policies & governance**: infosec policy, access-review cadence, onboarding/offboarding, vendor management.
- **Data retention & DPIA**: define retention for audit logs (and risk data, if you add app-layer risk-scoring); run a Legitimate Interest Assessment / DPIA (GDPR).
- **Incident response**: a documented plan, breach-notification workflow, and the NIS2/GDPR reporting timelines.
- **Independent assurance**: a SOC 2 audit, ISO 27001 certification, HIPAA risk assessment, or PCI ROC/SAQ — performed by an assessor against *your* running system.
- **Penetration testing**: schedule and act on a recurring third-party test.
- **Physical & network controls**: hosting, egress control (the complete SSRF answer), backups, key custody of the crypto master key.

## Evidence Cbox ID hands your auditor

- This mapping and the [standards conformance matrix](standards.md).
- The [security model](security.md) and threat model.
- A machine-readable **CycloneDX SBOM** and a passing dependency/license/vuln gate.
- A **tamper-evident audit trail** exportable as forensic evidence.
- Config that is **secure by default** (MFA available, breach screen on, deny-by-default).
