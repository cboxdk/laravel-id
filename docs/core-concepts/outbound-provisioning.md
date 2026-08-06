---
title: Outbound SCIM provisioning
description: Push user and membership changes OUT to downstream apps over their SCIM 2.0 endpoints — the mirror of the inbound directory
weight: 9
---

# Outbound SCIM provisioning

The `Provisioning` module (`src/Provisioning/`) is the platform acting as a SCIM
2.0 **client**: when a user or membership changes, it propagates that change to an
organization's downstream SaaS apps by calling **their** SCIM endpoints
(create/update/deactivate the user there).

## Inbound vs outbound — the mirror

The platform has two SCIM surfaces, pointing in opposite directions:

| | `src/Directory/` (+ `src/Api/`) | `src/Provisioning/` |
| --- | --- | --- |
| Role | SCIM **server** | SCIM **client** |
| Direction | provisioning comes **IN** (an IdP creates users on the platform) | provisioning goes **OUT** (the platform creates users on a downstream app) |
| Trigger | an inbound HTTP request | a platform domain event |
| Endpoint | the platform's `/scim/v2/Users` | the downstream app's `/Users` |

Both speak the same vocabulary, so they share one source of truth for it:
`Cbox\Id\Scim\ScimSchema` holds the RFC 7643/7644 URNs and the pure body builders
(`User` resource, `PatchOp`, `ListResponse`, error, filter), reused by the inbound
`Api\Support\ScimMapper` and the outbound client alike — the URNs are declared once.

## Statefulness — what makes this not a webhook

A webhook is fire-and-forget: sign the payload, POST it, retry on failure. SCIM
provisioning is **stateful**, because the downstream app assigns its own id to the
user and every later update must target that id. The `ProvisionedResource` model
is that state:

- `external_id` — the platform user id, sent as SCIM `externalId` (our stable
  handle on the remote record);
- `remote_id` — the id the downstream app returned on create (SCIM `id`), so an
  update PATCHes `/Users/{remote_id}` instead of creating a duplicate;
- `state` / `last_synced_at` — what we last pushed.

This is why the reconcile paths matter:

- **409 on create** (the user already exists remotely) → locate it by
  `externalId eq "…"` and PATCH it, rather than duplicating;
- **404 on update** (the remote record was deleted) → recreate it and capture the
  new id.

## The flow

```
domain event  →  listener (enqueue)  →  outbox  →  drain (deliver)  →  remote SCIM
```

1. **Translate + enqueue (request thread).** `ProvisionOnDomainEvent` listens for
   every `EventDelivered` and hands it to `ProvisioningService::enqueueForEvent()`,
   which maps the event to an operation (`user.created` → upsert, `user.deactivated`
   → deactivate, `organization.member_removed` → de-provision, …) and writes one
   durable `ProvisioningOperation` per in-scope connection. It never makes an HTTP
   call on the request thread. Deny-by-default: no connection in the environment ⇒
   nothing enqueued.
2. **Drain (queue worker).** `DrainProvisioningConnection` (one per connection,
   `ShouldBeUnique`) delivers the outbox with the SCIM statefulness above, bounded
   exponential backoff + jitter, a dead-letter cap, and a per-connection circuit
   breaker. `cbox-id:provisioning:drain` fans a job out to every active connection
   across all environments, once a minute.

## Isolation is structural

`ProvisioningConnection`, `ProvisionedResource` and `ProvisioningOperation` are all
`BelongsToEnvironment`, so the hard environment scope makes cross-environment
provisioning impossible by construction: a connection in env-A can only ever be
loaded, enqueued against, and delivered from within env-A. A queue worker has no
ambient environment, so the drain job **reconstructs** it: it reads the connection's
`environment_id` under `EnvironmentContext::withoutScope()` (a single-id system
read), then re-enters that environment with `runAs()` so every subsequent query
matches it — the same pattern the audit-streaming pump uses.

## Honesty: at-least-once

Delivery is **at-least-once**, not exactly-once. The outbox and `ShouldBeUnique`
keep the common case to a single delivery, and PATCH/`replace` operations are
idempotent, so a redelivery converges rather than corrupts. But a downstream app
that acknowledges after a network cut can still see a repeat — receivers should key
on `externalId`. This is a deliberate, documented trade-off, not a guarantee we
cannot keep.

## What it does not do

- It does not invent a `user.updated` event; it maps the platform's real events
  (and any a host emits). Attribute-level change detection is the host's to add.
- Group/entitlement provisioning is out of scope for this module today — it
  provisions the SCIM `User` resource.
