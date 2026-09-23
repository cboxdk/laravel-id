---
title: Reference
description: Exact shapes an app integrates against — token claims, the decision endpoint, and the webhook event catalogue
weight: 7
---

# Reference

The shapes a relying party, a resource server or a webhook receiver builds against. Each
page states what the framework emits today and when a field is absent, because an absent
claim is as much part of the contract as a present one.

- **[Token claims](token-claims.md)** — every claim on the access token, the ID token and
  UserInfo, including `org_role`, and which grants carry which.
- **[Decisions endpoint](decisions.md)** — `POST /oauth/decisions`: ReBAC tuples,
  entitlements, and app-scoped RBAC permission checks, with their request and response
  shapes and refusals.
- **[Webhook events](webhook-events.md)** — the catalogue: every event, what it means,
  what its payload carries, which names are legacy and which are not yet emitted.
