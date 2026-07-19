---
title: Core concepts
description: The architecture, the authorization decision plane, and entitlements
weight: 3
---

# Core concepts

How the platform is put together and the ideas you build against:

- **[Architecture & patterns](architecture.md)** — kernels vs. domain modules,
  contracts-first DI, and dogfooding.
- **[Platform operators](platform-operators.md)** — the identity above every
  environment: who provisions planes and can step into any one of them.
- **[Accounts, projects & the platform plane](accounts-and-projects.md)** — the
  self-serve hierarchy above environments: one login, many independently-billed IdP
  products (the Clerk "Applications" model), with billing anchored on the project.
- **[Environments & the isolation model](environments.md)** — the hard boundary
  above organizations (staging/prod, white-label).
- **[Authorization & the decision plane](authorization.md)** — live permission and
  entitlement decisions, the hot path, and the token hybrid.
- **[Entitlements & billing](entitlements-and-billing.md)** — capability gates fed by
  your billing engine, never billing state.
- **[On-prem licensing](on-prem-licensing.md)** — a signed, offline-verifiable license
  key unlocks paid entitlements on a self-hosted install, through the same gate.
- **[Usage metering](usage-metering.md)** — environment- and org-scoped usage counters
  for analytics and future soft gates; local measurement, distinct from billing.
- **[SIEM audit streaming](audit-streaming.md)** — mirror the hash-chained,
  environment-scoped audit trail out to a customer's SIEM, isolation intact.
- **[Outbound SCIM provisioning](outbound-provisioning.md)** — push user and
  membership changes OUT to downstream apps over their SCIM 2.0 endpoints; the
  stateful mirror of the inbound directory.
- **[OTP delivery channels](otp-channels.md)** — delivered one-time passcodes
  (email/SMS) as a verification and MFA factor, and the caps that make a short
  code safe.
- **[AI token vault](token-vault.md)** — seal downstream third-party credentials
  and broker short-lived, deny-by-default leased access to autonomous / AI agents.
- **[CIBA backchannel approval](ciba.md)** — OpenID Connect Client-Initiated
  Backchannel Authentication: human-in-the-loop approval for agent actions.
- **[Access governance](access-governance.md)** — IGA: access-certification
  campaigns and Segregation-of-Duties policies over roles and memberships.
- **[External actions & inline hooks](external-actions.md)** — synchronous
  extension points that enrich or veto an operation (in-process or external HTTP).
