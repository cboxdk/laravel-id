---
title: Usage metering
description: Environment- and organization-scoped usage counters for analytics and future plan-gates — the local measurement layer, distinct from billing
weight: 8
---

# Usage metering

## TL;DR

- **Metering counts what an org *did*** — sign-ins, tokens issued, members added — as
  environment- and organization-scoped per-day counters. It is the *measurement*
  layer, the counterpart to [entitlements](entitlements-and-billing.md), which gate
  what an org *may do*.
- **It is local, not billing.** The counters live in your Cbox ID database and drive
  dashboards and (later) soft plan-gates. They work on a self-hosted install with **no
  billing service at all**. Billing-grade metering + quota enforcement is a separate,
  app-embedded concern — see [the boundary](#the-boundary-metering-vs-billing) below.
- **One shared vocabulary.** Metric keys are namespaced `auth.*` (`auth.login`,
  `auth.user`, `auth.id_token`, …) so a local analytics counter, a billing meter, and
  a future gate all mean the same thing by "a login".
- **Recording is automatic and exactly-once.** Domain events are metered off the
  transactional outbox via a shared event→metric map, deduped by event id
  so at-least-once delivery never double-counts.

```
  domain events (outbox)
        │  EventMetricMap: type → auth.* metric
        ▼
  UsageMeter.record(metric, 1, org)      ← env + org scoped, per-day, atomic
        │
        ├──► total / series / snapshot    → dashboards, soft gates (self-hosted)
        └──► (optional) billing bridge     → your billing meter (SaaS only)
```

## The meter

Resolve `Cbox\Id\Kernel\Usage\Contracts\UsageMeter` from the container.

```php
use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;

$meter = app(UsageMeter::class);

// Record — increment a metric for the current environment, attributed to an org.
$meter->record('auth.login', 1, $organizationId);

// Read.
$meter->total('auth.login', $organizationId);                 // int, this org
$meter->total('auth.login', null);                            // across the environment
$meter->series('auth.login', $organizationId, $since, $until); // ['Y-m-d' => int] for charts
$meter->snapshot($organizationId, $since, $until);            // ['metric' => total] for a panel
```

- **`organizationId` null on `record()`** is a system-scoped count (no org); **null on a
  query** means "across the whole environment".
- Counters are **atomic** — a find-or-create of the day's row plus an atomic
  `count = count + n` UPDATE, serialised by a unique index and a transaction retry, so
  concurrent increments are never lost (SQLite-portable, the house pattern).
- Everything is **environment-owned**: a counter recorded in one environment is
  structurally invisible in another, exactly like every other tenant-scoped model.

## Automatic recording

You rarely call `record()` by hand. `RecordUsageOnDomainEvent` listens for delivered
domain events and meters the mapped ones. The mapping is the single source of truth,
`Cbox\Id\Kernel\Usage\EventMetricMap`:

```php
use Cbox\Id\Kernel\Usage\EventMetricMap;

EventMetricMap::for('user.login');   // UsageMetric::Login  ('auth.login')
EventMetricMap::all();               // the whole event-type → metric map
```

Because delivery off the outbox is **at-least-once**, and a raw increment is not
idempotent, each event is metered **exactly once** — a marker row keyed on the event id
(`usage_metered_events`) lets only the first delivery through. Add a metered event by
adding a map entry; nothing at the emit site changes.

Metric keys are the `UsageMetric` enum (`Cbox\Id\Kernel\Usage\Enums\UsageMetric`) —
`record()` accepts any string, but these are the stable, first-party names to build on.

## The boundary: metering vs billing

Cbox ID's metering is **local analytics**. It is deliberately *not* your billing meter:

| | Cbox ID `UsageMeter` | Billing client |
| --- | --- | --- |
| Question | what did this org *do*? | what do we *charge*, and is it over quota? |
| Authority | local counters | the remote billing service |
| Enforcement | none (measurement only) | hot-path quota gates (`reserve()` → `QuotaExceeded`) |
| Needs a billing service | no — works self-hosted | yes |

They share the `auth.*` vocabulary, so a **bridge** can forward the same events to
billing without either side re-deriving anything:
[`cboxdk/laravel-id-billing-bridge`](https://github.com/cboxdk/laravel-id-billing-bridge)
is one `EventDelivered` listener that maps via `EventMetricMap` and calls the billing
client's `UsageBuffer::record()`. It is the *only* package that depends on both Cbox ID
and the billing client, so the self-hostable app stays billing-free. Compose it in the
SaaS; leave it out of a self-hosted install.

This keeps the [entitlements boundary](entitlements-and-billing.md) intact: entitlements
are still pure capability gates fed by billing, and never a usage count. Metering is a
separate, local signal — and a future soft gate is simply "read the counter, compare to
the plan's allowance."

## Configuration

```php
// config/cbox-id.php
'usage' => [
    'enabled' => env('CBOX_ID_USAGE_ENABLED', true),
],
```

Disabled, no counters or dedup markers are written and the event listener is never
registered — a deployment that doesn't want metering pays nothing.

## Testing

Swap the fake in with the `InteractsWithUsage` trait and assert on recorded increments:

```php
use Cbox\Id\Kernel\Usage\Testing\InteractsWithUsage;

$usage = $this->fakeUsage();
// ... exercise the code ...
$usage->assertIncremented('auth.login');
$usage->assertIncrementedCount('auth.login', 1);
```
