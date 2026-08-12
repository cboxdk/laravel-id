---
title: Background work
description: The queue worker and scheduler the platform needs, the outbox relay, webhook delivery, backlog monitoring and retention
weight: 1
---

# Background work

Almost nothing in this platform is delivered on the request thread. Emitting a domain
event writes a row; registering a webhook writes a row. A **scheduler** turns those rows
into work, and a **queue worker** performs the work that talks to the network. Neither is
started by the package, and neither is optional.

> **If you are upgrading an existing deployment, read this first.** Webhook delivery used
> to happen inline. It is now a queued job (`Cbox\Id\Webhooks\Jobs\DeliverWebhook`). On a
> deployment whose queue connection is `database`, `redis` or SQS with **no worker
> running**, every webhook is recorded, queued and never sent — the delivery row stays
> `pending`, no exception is raised, no log line is written, and the admin console shows
> the endpoint as healthy. Start a worker before or with the upgrade.

## What must be running

| Process | Command | What it drives | What breaks without it |
|---|---|---|---|
| Scheduler | `php artisan schedule:run` every minute (or `schedule:work` in dev) | the outbox relay, the webhook retry sweep, the provisioning drain, the SIEM pump, campaign auto-close, the nightly prune | Nothing is delivered at all. Domain events accumulate in `events`, so no webhook fires, no usage is metered, outbound SCIM never runs and no host listener is ever called. |
| Queue worker | `php artisan queue:work` | `DeliverWebhook`, `DrainProvisioningConnection`, `PumpAuditStream`, `SyncAppManifestJob` | The scheduler still records and enqueues, but nothing performs the outbound HTTP. Webhooks sit `pending`, SCIM operations sit `pending`, SIEM batches are never shipped. |

```bash
# production: one cron entry, plus a supervised worker
* * * * * cd /path/to/app && php artisan schedule:run >> /dev/null 2>&1
php artisan queue:work --tries=1
```

`DeliverWebhook` manages its own retries through the delivery row (see below), so it does
not need queue-level retries to be correct.

Both failures are silent by construction, and they fail in different ways: without the
scheduler the outbox depth climbs and `cbox-id:events:backlog` says so; without a worker
the outbox drains normally — the relay's own work succeeds — while `webhook_deliveries`
fills with `pending` rows. Monitor both.

### The `sync` connection

If the application's default queue connection is `sync`, Laravel runs the job inline in
the dispatching process, so a `sync` deployment still delivers without a worker. It does
so on the scheduler thread, though, which reintroduces exactly the head-of-line blocking
the queue exists to remove: one blackholing receiver stalls every other tenant's relay
pass. Use `sync` for local development and tests, not for a deployment with real
endpoints.

To keep webhook egress off the application's main queue, set `webhooks.queue_connection`
and/or `webhooks.queue`; both are optional and are applied per job in
`HttpWebhookDispatcher::enqueue()`.

## The outbox relay

`cbox-id:events:relay` is the single chokepoint every subscriber hangs off. `EventBus::emit()`
only writes an `events` row inside the caller's transaction; the relay is what dispatches
`EventDelivered` to listeners — webhook fan-out, usage metering, outbound provisioning,
group-to-role reconciliation, and the host's own listeners.

It is registered automatically by `EventsServiceProvider` when
`cbox-id.events.schedule_relay` is true (the default):

| Property | Default | Key |
|---|---|---|
| Cadence | every minute | `events.relay_cadence` |
| Events per pass | 100 | `events.relay_limit` |
| Reclaim window | 300 s | `events.reclaim_after_seconds` |
| Attempts before dead-letter | 12 | `events.max_attempts` |

`relay_cadence` is a closed set (`RelayCadence`) — `every_minute`, `every_two_minutes`,
`every_five_minutes`, `every_ten_minutes`, `every_fifteen_minutes`,
`every_thirty_minutes`, `hourly`. An unrecognised value falls back to `every_minute`
rather than leaving the relay unscheduled, because a typo in a free-form cron string
would silently stop the entire fan-out.

Each pass **claims** a batch (a short transaction, `FOR UPDATE SKIP LOCKED` on
Postgres/MySQL, a claim token everywhere) so two relays — overlapping ticks, or two app
instances — never deliver the same event twice. A claim older than the reclaim window
belongs to a relay that died mid-pass and becomes eligible again. Delivery is honestly
**at-least-once**.

A listener that throws does not abort the pass: the claim is released, `attempts` is
incremented and the event is retried on the next pass. Once `max_attempts` is reached the
row is dead-lettered (`dead_lettered_at` stamped, logged at `critical`) and never claimed
again. Dead-lettered rows are excluded from the backlog reading — they are an operator's
queue, not the relay's.

Drive it by hand instead by setting `events.schedule_relay` to false and running:

```bash
php artisan cbox-id:events:relay --limit=100
```

## Webhook delivery

The fan-out and the send are deliberately separate.

1. The relay dispatches `EventDelivered`. `WebhookServiceProvider`'s listener asks
   `HttpWebhookDispatcher::dispatch()` to write one `webhook_deliveries` row per matching
   **active** endpoint (with an atomically allocated per-endpoint `sequence`), then queues
   one `DeliverWebhook` job per row. No socket is opened on the relay thread.
2. A worker runs the job. It reads the delivery's `environment_id` with the environment
   scope suspended (a worker carries no ambient environment), re-enters that environment,
   and performs the signed HTTP POST.

The row is durable **before** the job exists, which is what makes the rescue path below
meaningful.

### The uniqueness lock and the stranded-delivery rescue

`DeliverWebhook` implements `ShouldBeUnique`, keyed by the delivery id, with `$uniqueFor`
read from `webhooks.stranded_after_seconds` (default 900). The retry sweep runs every
minute, so without the lock a backed-up queue would accumulate several jobs for the same
delivery and send it more than once.

The lock TTL and the stranded window are **the same number on purpose**:

- While the lock holds, a job for this delivery is presumed alive, so the sweep's
  re-enqueue is correctly suppressed.
- The moment the delivery counts as stranded, the lock has expired, so the sweep can
  actually rescue it.

A longer lock ceiling would wedge the rescue shut. If you raise
`stranded_after_seconds`, both move together — that is the point of the single key.

The sweep (`cbox-id:webhooks:retry`, registered every minute by `WebhookServiceProvider`
when `webhooks.schedule_retries` is true) re-enqueues up to `webhooks.retry_limit` (50)
rows per pass, oldest first:

- `failed` deliveries whose `next_retry_at` has elapsed, and
- `pending` deliveries older than `stranded_after_seconds` — the job was lost, the worker
  died, or the queue was flushed.

It also settles deliveries whose endpoint has been deleted: endpoint deletion does not
cascade, so those rows are marked `exhausted` in a single set-based update rather than
being re-selected forever at the head of every sweep.

### Backoff and the dead-letter cap

Each failed attempt sets `next_retry_at` to `now() + min(60, 2 ** attempt)` minutes — so
2, 4, 8, 16, 32, then 60 minutes for every attempt after that. When `attempt` reaches
`webhooks.max_attempts` (12) the delivery becomes `exhausted`: no further retries, and it
becomes eligible for pruning on the `webhook_deliveries` retention clock.

A URL refused by the SSRF guard is retried but **never** counted against the endpoint's
health — a refused URL is a policy decision about a misconfiguration, not evidence that
the receiver is unhealthy.

### The per-endpoint circuit breaker

After `webhooks.circuit_breaker.failure_threshold` (5) consecutive failures,
`EndpointCircuitBreaker` opens: it stamps `circuit_opened_at` and delivery to that one
endpoint pauses for `circuit_breaker.cooldown_seconds` (300). Once the cooldown elapses a
single probe is admitted; a success closes the breaker and resets the counter, a failure
re-opens it. A blackholing receiver therefore costs one timeout per cooldown window
instead of one timeout per event.

Nothing is dropped. A delivery that arrives while the breaker is open is written, marked
`failed` with `next_retry_at` set to the breaker's close time, and **keeps its attempt
count** — the trip is the endpoint's fault, not that delivery's.

The breaker records on the endpoint's own health columns — `consecutive_failures`,
`circuit_opened_at`, `last_success_at`, `last_error` — and **never on `status`**.
`status` (`active` / `paused`) is the operator's own intent: a breaker trip can never
overwrite a `paused` an operator set, and closing the breaker can never un-pause an
endpoint. Read the trip through `EndpointCircuitBreaker::health()`, which returns an
`EndpointHealth` value object (including `circuitClosesAt`) with no column or config
knowledge required.

## Monitoring: the outbox backlog

Relay lag is otherwise invisible — a stalled relay looks exactly like an idle one.

Every relay pass logs the depth: `debug` normally, and `warning` once the **waiting**
depth reaches `events.backlog_warning_threshold` (1000). The package depends on no
telemetry runtime, so this is a log line plus a resolvable `RelayBacklog` contract, not a
metrics call. A host with metrics wiring can resolve `RelayBacklog` and publish
`depth()` as a gauge.

For everything else there is a command:

```bash
php artisan cbox-id:events:backlog
php artisan cbox-id:events:backlog --json
php artisan cbox-id:events:backlog --fail-over=500   # exit 1 when waiting >= 500
```

The table form prints `waiting`, `in flight`, `total`, `oldest undelivered` and
`oldest age (s)`. `--json` prints the same reading as an object:

```json
{"waiting":0,"in_flight":3,"total":3,"oldest_undelivered_at":"2026-07-25T09:14:02+00:00","oldest_age_seconds":4}
```

That is healthy: nothing is waiting, three rows are claimed by a relay that is inside its
reclaim window, and the oldest undelivered event is seconds old.

```json
{"waiting":8412,"in_flight":0,"total":8412,"oldest_undelivered_at":"2026-07-24T22:03:11+00:00","oldest_age_seconds":40251}
```

That is a stopped relay: thousands waiting, nothing in flight, and the oldest event is
eleven hours old. Depth alone is not enough to alarm on — a large but *moving* backlog is
fine and a small but *ageing* one is not — which is why the oldest age travels with the
count.

`--fail-over=N` makes the command a health check straight from cron or a Kubernetes
probe: it exits non-zero when the waiting depth is at or above `N`.

Note what the reading counts: `waiting` is unclaimed rows plus rows whose claim is older
than `events.reclaim_after_seconds`; `inFlight` is claimed rows still inside that window.
Dead-lettered rows are excluded from both, deliberately — counting them would create a
permanent floor that no amount of relay capacity could bring down, hiding a real backlog
behind it.

## Retention and pruning

Nothing in the platform deletes rows on its own. `cbox-id:prune` is the sweep, scheduled
daily at `prune.time` (`03:10`) by `MaintenanceServiceProvider` when `prune.schedule` is
true. It runs unscoped by environment on purpose — it is a deployment-wide maintenance
pass, like the relay — and deletes in bounded chunks (`prune.chunk`, 1000) so it never
takes a table-wide lock.

`retention_days` is how long a row is kept **after it is already dead** — not how long a
token lives.

| Table | Default retention | A row is eligible when |
|---|---|---|
| `dpop_proofs` | 1 day | `expires_at` is past the cutoff |
| `consumed_assertions` | 1 day | `expires_at` is past the cutoff |
| `oauth_authorization_codes` | 1 day | `expires_at` is past the cutoff |
| `oauth_access_tokens` | 7 days | `expires_at` is past the cutoff |
| `oauth_refresh_tokens` | 30 days | `expires_at` is past the cutoff (reuse detection needs the consumed row until then) |
| `events` | 30 days | `dispatched_at` **or** `dead_lettered_at` is past the cutoff — an undispatched row is never deleted, however old |
| `auth_sessions` | 30 days | `expires_at` is past the cutoff |
| `usage_metered_events` | 30 days | `created_at` is past the cutoff |
| `webhook_deliveries` | 30 days | status is `delivered` or `exhausted` **and** `updated_at` is past the cutoff — a `failed` row is still owed a retry |
| `provisioning_operations` | 30 days | status is `delivered` or `exhausted` **and** `updated_at` is past the cutoff |

`dpop_proofs` is the one to watch: one INSERT per DPoP-protected request, with a unique
index that grows with total request volume.

```bash
php artisan cbox-id:prune --dry-run                       # count, delete nothing
php artisan cbox-id:prune --table=dpop_proofs             # one table (repeatable)
php artisan cbox-id:prune --table=events --table=auth_sessions
php artisan cbox-id:prune --chunk=500                     # smaller statements
```

`--dry-run` is the right first move on a deployment that has never been swept: the first
pass may be very large. An unknown `--table` value fails the command rather than silently
sweeping everything. A table that is not installed (a host may install only part of the
platform) is skipped, not treated as an error.

Schedule keys: `cbox-id.prune.schedule` (on/off), `cbox-id.prune.time` (`HH:MM`, daily).
The registered schedule entry is named `cbox-id:prune` and runs `withoutOverlapping()`.

### Why `audit_logs` is never pruned

`audit_logs` is not merely omitted from the defaults — it is **not a case of
`PrunableTable` at all**, so it cannot be swept even deliberately:

```bash
php artisan cbox-id:prune --table=audit_logs
# Unknown table 'audit_logs'. Known: dpop_proofs, consumed_assertions, ...
# exit code 1
```

The trail is a hash-chained, tamper-evident structure, not a log file:

- `AuditLog::verifyChain()` walks from `fromSequence` (default 1) and reports a sequence
  gap or reordering the moment a row is missing. Pruning **below** a checkpoint therefore
  breaks the default full-chain verify.
- `verifyCheckpointAnchor()` exists specifically to catch tail deletion: it requires the
  entry anchored by the last signed checkpoint to still be present with the same hash.
  Pruning **up to and including** a checkpoint removes exactly the row that check reads.

So there is no "prune up to a verified checkpoint" that leaves verification intact. A
prune that makes the tamper-evidence report tampering has destroyed the control it exists
to provide. `cbox-id:prune` prints this reminder on every run, so a clean prune report is
never read as "everything is bounded now".

Bounding audit growth is a real need, and the answer is to get entries **out** rather than
to delete them: `src/AuditStreaming/` mirrors the trail to a customer's SIEM, carrying the
chain metadata for dedup and gap detection at the destination. An archive step that
re-anchors a surviving prefix and signs a new genesis would be a feature in its own right;
it is deliberately out of scope rather than approximated unsafely.

### The empty-env trap

Setting a retention env var to an **empty value** does not fall back to the default — it
**disables pruning for that table**:

```dotenv
CBOX_ID_PRUNE_EVENTS=          # NOT "use the default 30"
```

`env('CBOX_ID_PRUNE_EVENTS', 30)` returns `''` (the variable is set, so the default is
never reached), and `Pruner::retentionDays()` treats `null`, `''` and `false` alike as
"the operator turned this table's sweep off". The table is then reported as
`skipped (retention disabled in config)` on every run, and grows forever.

Only an **absent** key falls back to `PrunableTable::defaultRetentionDays()`. To keep a
table's default, leave the variable out of `.env` entirely; to disable a sweep on purpose,
set the config value to `null` explicitly so the intent is readable. Check with
`php artisan cbox-id:prune --dry-run` — anything reading `skipped` is not being swept.

## Audit checkpointing — available, and off by default

The hash chain catches **modification** and **sequence gaps** on its own. It cannot catch
**truncation**: delete the newest N entries and what remains is a shorter, perfectly valid
chain. A signed checkpoint is the only thing that catches that — `verifyChain()` requires
the entry a checkpoint anchors to still be present with the same hash.

```bash
php artisan cbox-id:audit:checkpoint --dry-run          # what would be signed, per chain
php artisan cbox-id:audit:checkpoint                    # sign every advanced chain
php artisan cbox-id:audit:checkpoint --scope=org_01H…   # one chain (repeatable)
php artisan cbox-id:audit:checkpoint --environment=env_01H…
php artisan cbox-id:audit:checkpoint --force            # re-sign an unchanged head
```

One pass enumerates every `(environment, scope)` chain straight out of `audit_logs` —
that is exactly the set of chains that exists, and it includes the platform plane, which
has no environment row — then re-enters each chain's environment and signs its head. A
chain whose head is already attested is **skipped**, so the pass is idempotent and costs
one row per *active* chain per run and nothing for the rest. It takes no lock and writes
no `audit_logs` row, so it is safe to run beside live appends; an append that lands
mid-pass simply belongs to the next checkpoint.

### Why the schedule ships disabled

`cbox-id.audit.checkpoint.schedule` defaults to **false**. Signing the first checkpoint is
a **one-way door**: a checkpoint attests the chain's hashes *as they are today*, and is
meant to be exported to an append-only store you cannot retract. The planned GDPR-erasure
design needs exactly one **re-chain** of the existing rows — hashing the *ciphertext* of
`ip` and `context` rather than the plaintext, so destroying a per-subject key leaves every
hashed byte unchanged and `verifyChain()` still passes bit-for-bit. Any checkpoint signed
before that re-chain would afterwards report tampering that never happened.

No checkpoint has ever been signed, so that window is still open. Enable in this order:

1. sign and retain each chain's head hash and row count **out of band** (`--dry-run`
   prints the head sequence per chain);
2. introduce `chain_version` + ciphertext hashing;
3. run the one-time re-chain;
4. **then** set `CBOX_ID_AUDIT_CHECKPOINT_SCHEDULE=true`.

**If no re-chain is in your future, turn it on now** — until you do, a truncated trail is
undetectable. Full detail in [`UPGRADING.md`](../../UPGRADING.md).

## Other scheduled work

Registered by their own modules on the same `withoutOverlapping()` pattern, each gated by
a config flag so a host can drive it from its own scheduler instead:

| Schedule name | Cadence | Config key |
|---|---|---|
| `cbox-id:events:relay` | `events.relay_cadence` (every minute) | `cbox-id.events.schedule_relay` |
| `cbox-id:webhooks:retry` | every minute | `cbox-id.webhooks.schedule_retries` |
| `cbox-id:provisioning:drain` | every minute | `cbox-id.provisioning.schedule` |
| `cbox-id:audit-streams:pump` | every minute | `cbox-id.audit_streaming.schedule` |
| `cbox-id:governance:close-overdue` | every minute | `cbox-id.governance.schedule` |
| `cbox-id:prune` | daily at `prune.time` | `cbox-id.prune.schedule` |
| `cbox-id:audit:checkpoint` | daily at `audit.checkpoint.time` | `cbox-id.audit.checkpoint.schedule` — **off by default**, see above |
| `cbox-id:access-control:sync-manifests` | hourly | `cbox-id.access_control.schedule` |
| `cbox-id:directory:sync` | hourly | `cbox-id.directory.schedule` |

Nothing here retires a signing key. `cbox-id:keys:rotate --retire-after=<hours>` is the
only thing that does, and it is deliberately NOT scheduled — a host runs it on its own
cadence. It is called out because "the scheduler handles cleanups" reads as if it covers
key retirement, and it does not.

`cbox-id:webhooks:retry` is a scheduled closure rather than an Artisan command — to drive
it yourself, disable `webhooks.schedule_retries` and call
`WebhookDispatcher::retryPending($limit)`.

## Configuration

| Dot path | Env var | Default | Effect |
|---|---|---|---|
| `cbox-id.events.schedule_relay` | `CBOX_ID_EVENTS_SCHEDULE_RELAY` | `true` | Register the relay on the scheduler. Off means you must call `EventBus::flushPending()` yourself. |
| `cbox-id.events.relay_limit` | `CBOX_ID_EVENTS_RELAY_LIMIT` | `100` | Events claimed and delivered per pass. |
| `cbox-id.events.relay_cadence` | `CBOX_ID_EVENTS_RELAY_CADENCE` | `every_minute` | How often the relay runs. Closed set; an unknown value falls back to `every_minute`. |
| `cbox-id.events.reclaim_after_seconds` | `CBOX_ID_EVENTS_RECLAIM_AFTER_SECONDS` | `300` | How long a claimed-but-undelivered event waits before another relay may take it. |
| `cbox-id.events.max_attempts` | `CBOX_ID_EVENTS_MAX_ATTEMPTS` | `12` | Failed deliveries before an outbox row is dead-lettered. |
| `cbox-id.events.backlog_warning_threshold` | `CBOX_ID_EVENTS_BACKLOG_WARNING_THRESHOLD` | `1000` | Waiting depth at which each pass logs `warning` instead of `debug`. |
| `cbox-id.webhooks.schedule_retries` | `CBOX_ID_WEBHOOKS_SCHEDULE_RETRIES` | `true` | Register the per-minute retry/rescue sweep. |
| `cbox-id.webhooks.retry_limit` | `CBOX_ID_WEBHOOKS_RETRY_LIMIT` | `50` | Deliveries one sweep re-enqueues. |
| `cbox-id.webhooks.stranded_after_seconds` | `CBOX_ID_WEBHOOKS_STRANDED_AFTER_SECONDS` | `900` | Both the job's unique-lock TTL and how long a `pending` delivery may sit before the sweep rescues it. |
| `cbox-id.webhooks.max_attempts` | `CBOX_ID_WEBHOOKS_MAX_ATTEMPTS` | `12` | Attempts before a delivery is dead-lettered (`exhausted`). |
| `cbox-id.webhooks.queue_connection` | `CBOX_ID_WEBHOOKS_QUEUE_CONNECTION` | unset | Queue connection for `DeliverWebhook`. Unset uses the application default. |
| `cbox-id.webhooks.queue` | `CBOX_ID_WEBHOOKS_QUEUE` | unset | Queue name for `DeliverWebhook`, to isolate egress. |
| `cbox-id.webhooks.circuit_breaker.failure_threshold` | `CBOX_ID_WEBHOOKS_CB_FAILURE_THRESHOLD` | `5` | Consecutive failures before an endpoint's breaker opens. |
| `cbox-id.webhooks.circuit_breaker.cooldown_seconds` | `CBOX_ID_WEBHOOKS_CB_COOLDOWN_SECONDS` | `300` | How long an open breaker skips the endpoint before admitting a probe. |
| `cbox-id.prune.schedule` | `CBOX_ID_PRUNE_SCHEDULE` | `true` | Register the daily sweep. |
| `cbox-id.prune.time` | `CBOX_ID_PRUNE_TIME` | `03:10` | Time of day for the sweep (`HH:MM`; a malformed value falls back to `03:10`). |
| `cbox-id.prune.chunk` | `CBOX_ID_PRUNE_CHUNK` | `1000` | Rows deleted per statement. `--chunk` overrides per run. |
| `cbox-id.prune.retention_days.dpop_proofs` | `CBOX_ID_PRUNE_DPOP_PROOFS` | `1` | Days a dead row is kept. |
| `cbox-id.prune.retention_days.consumed_assertions` | `CBOX_ID_PRUNE_CONSUMED_ASSERTIONS` | `1` | Days a dead row is kept. |
| `cbox-id.prune.retention_days.oauth_authorization_codes` | `CBOX_ID_PRUNE_AUTHORIZATION_CODES` | `1` | Days a dead row is kept. |
| `cbox-id.prune.retention_days.oauth_access_tokens` | `CBOX_ID_PRUNE_ACCESS_TOKENS` | `7` | Days a dead row is kept. |
| `cbox-id.prune.retention_days.oauth_refresh_tokens` | `CBOX_ID_PRUNE_REFRESH_TOKENS` | `30` | Days a dead row is kept. |
| `cbox-id.prune.retention_days.events` | `CBOX_ID_PRUNE_EVENTS` | `30` | Days a dispatched or dead-lettered outbox row is kept. |
| `cbox-id.prune.retention_days.auth_sessions` | `CBOX_ID_PRUNE_AUTH_SESSIONS` | `30` | Days an expired session row is kept. |
| `cbox-id.prune.retention_days.usage_metered_events` | `CBOX_ID_PRUNE_USAGE_MARKERS` | `30` | Days a metering dedup marker is kept. |
| `cbox-id.prune.retention_days.webhook_deliveries` | `CBOX_ID_PRUNE_WEBHOOK_DELIVERIES` | `30` | Days a terminal delivery row is kept. |
| `cbox-id.prune.retention_days.provisioning_operations` | `CBOX_ID_PRUNE_PROVISIONING_OPERATIONS` | `30` | Days a terminal provisioning operation is kept. |
| `cbox-id.audit.checkpoint.schedule` | `CBOX_ID_AUDIT_CHECKPOINT_SCHEDULE` | **`false`** | Register the daily audit-checkpoint pass. Off by default because the first signature is a one-way door — see [above](#why-the-schedule-ships-disabled). |
| `cbox-id.audit.checkpoint.time` | `CBOX_ID_AUDIT_CHECKPOINT_TIME` | `02:40` | Time of day for the checkpoint pass (`HH:MM`; a malformed value falls back to `02:40`). |
| `cbox-id.provisioning.schedule` | `CBOX_ID_PROVISIONING_SCHEDULE` | `true` | Register the per-minute outbound-SCIM drain. |
| `cbox-id.audit_streaming.schedule` | `CBOX_ID_AUDIT_STREAMING_SCHEDULE` | `true` | Register the per-minute SIEM pump. |
| `cbox-id.governance.schedule` | `CBOX_ID_GOVERNANCE_SCHEDULE` | `true` | Register the per-minute overdue-campaign close. |

Any retention key set to an empty value disables that table's sweep — see
[the empty-env trap](#the-empty-env-trap).

## Honest scope

- Domain-event delivery and webhook delivery are **at-least-once**, not exactly-once. The
  claim, the delivery row's terminal statuses and the job's uniqueness lock make a second
  send unlikely, not impossible; receivers must be idempotent on `delivery_id`.
- The backlog signal is a log line and a contract, not metrics. The package deliberately
  depends on no telemetry runtime — wiring `RelayBacklog` to your own gauge is the host's
  job.
- Neither the scheduler nor the worker is supervised by this package. Liveness of both is
  a deployment concern; `cbox-id:events:backlog --fail-over=N` is the hook to hang a probe
  on for the relay half, and a `pending`-row count on `webhook_deliveries` for the worker
  half.
- `audit_logs` is unbounded by design. Streaming it out is available today; a re-anchoring
  archive step is not.
- Tail-deletion detection is **available but not on**. Until you enable
  `audit.checkpoint.schedule` (or run the command yourself), `audit_checkpoints` stays
  empty, `verifyChain()` has no checkpoint to cross-check, and a trail truncated at the
  tail verifies clean. That is the honest state of the control, and the reason for the
  default is above.
