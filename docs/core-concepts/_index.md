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
- **[Environments & the isolation model](environments.md)** — the hard boundary
  above organizations (staging/prod, white-label).
- **[Authorization & the decision plane](authorization.md)** — live permission and
  entitlement decisions, the hot path, and the token hybrid.
- **[Entitlements & billing](entitlements-and-billing.md)** — capability gates fed by
  your billing engine, never billing state.
- **[SIEM audit streaming](audit-streaming.md)** — mirror the hash-chained,
  environment-scoped audit trail out to a customer's SIEM, isolation intact.
- **[Outbound SCIM provisioning](outbound-provisioning.md)** — push user and
  membership changes OUT to downstream apps over their SCIM 2.0 endpoints; the
  stateful mirror of the inbound directory.
- **[OTP delivery channels](otp-channels.md)** — delivered one-time passcodes
  (email/SMS) as a verification and MFA factor, and the caps that make a short
  code safe.
