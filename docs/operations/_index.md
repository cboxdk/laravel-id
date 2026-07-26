---
title: Operations
description: What has to be running for the platform to deliver anything, and how to keep it bounded
weight: 6
---

# Operations

The platform does almost nothing on the request thread. Events go to an outbox, webhooks
and outbound provisioning go to a queue, and growing tables are swept on a schedule — so a
deployment that looks completely healthy can be delivering nothing at all.

- **[Background work](background-work.md)** — the queue worker and the scheduler you must
  run, the domain-event relay, asynchronous webhook delivery (uniqueness lock, stranded
  rescue, backoff, per-endpoint circuit breaker), backlog monitoring with
  `cbox-id:events:backlog`, and retention via `cbox-id:prune` — including why `audit_logs`
  is never pruned.
