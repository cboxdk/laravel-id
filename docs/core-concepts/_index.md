---
title: Core concepts
description: The architecture, the authorization decision plane, and entitlements
weight: 3
---

# Core concepts

How the platform is put together and the ideas you build against:

- **[Architecture & patterns](architecture.md)** — kernels vs. domain modules,
  contracts-first DI, and dogfooding.
- **[Environments & the isolation model](environments.md)** — the hard boundary
  above organizations (staging/prod, white-label).
- **[Authorization & the decision plane](authorization.md)** — live permission and
  entitlement decisions, the hot path, and the token hybrid.
- **[Entitlements & billing](entitlements-and-billing.md)** — capability gates fed by
  your billing engine, never billing state.
