---
title: Stream audit events to a SIEM
description: Enable an audit stream to Splunk for a single environment, and deliver it
weight: 8
---

# Stream audit events to a SIEM

Goal: mirror one environment's hash-chained audit trail to a customer's Splunk HTTP
Event Collector (HEC). The same steps work for Elastic ECS, Graylog GELF, an
ArcSight/CEF collector, or a generic JSON endpoint — only the `Destination` changes.

See [SIEM audit streaming](../core-concepts/audit-streaming.md) for the mental model
and the isolation guarantee.

## 1. Register the stream — inside the environment

A stream is [environment-owned](../core-concepts/environments.md): it is created
stamped with the **current** environment, and only that environment's audit entries
will ever flow to it. Create it while acting as the target environment.

```php
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\Destination;

$registered = app(EnvironmentContext::class)->runAs($productionEnvironment, function () {
    return app(LogStreams::class)->create(
        name: 'acme-splunk',
        destination: Destination::SplunkHec,
        endpointUrl: 'https://http-inputs-acme.splunkcloud.com/services/collector',
        secret: $hecToken,   // the customer's HEC token — stored encrypted at rest
    );
});

// The plaintext secret is revealed exactly once, here. Only ciphertext is persisted.
$registered->secret;          // capture now if you generated it; it is gone after
$registered->stream->id;      // the stream id
```

The endpoint URL is **SSRF-checked before it is stored** — a stream pointing at a
loopback, private, link-local, reserved, or cloud-metadata address is refused. (An
on-prem single-tenant install that must reach an internal collector can disable the
guard with `siem.http.verify_url` — never do this in a multi-tenant deployment; see
the [security note](../security/audit-streaming.md).)

## 2. Record audit events as usual

Nothing about recording changes. Every entry recorded while that environment is
active is mirrored to the stream in the same transaction:

```php
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;

app(AuditLog::class)->record(AuditEvent::forUser('user.login', $userId));
```

With no stream configured for the environment this is a no-op beyond the normal
record — deny-by-default, no overhead.

## 3. Deliver

Delivery is asynchronous, off the request thread. The platform schedules a per-minute
pump for every enabled stream across every environment (each job reconstructs its
own stream's environment before delivering). Just run the scheduler and a queue
worker:

```bash
php artisan schedule:work      # dispatches cbox-id:audit-streams:pump every minute
php artisan queue:work         # runs the per-stream PumpAuditStream jobs
```

To drive it by hand instead — for example from your own scheduler — disable the
built-in schedule and call the command yourself:

```php
// config/cbox-id.php
'audit_streaming' => ['schedule' => false],
```

```bash
php artisan cbox-id:audit-streams:pump
```

## 4. Refine the mapping (optional)

`DefaultSiemEventMapper` derives a sensible `EventCategory` / `Outcome` / `Severity`
from the action's prefix (documented on the class). To tune it for your action
vocabulary, bind your own `SiemEventMapper` — but keep the two invariants the
receiver relies on: the event **id must be the entry hash**, and the context must
carry `sequence`, `hash`, `prev_hash`, and `organization_id`.

```php
use Cbox\Id\AuditStreaming\Contracts\SiemEventMapper;

$this->app->singleton(SiemEventMapper::class, MyMapper::class);
```

## Testing it

The package ships `InteractsWithAuditStreaming`, which swaps the HTTP sink for an
in-memory fake and pumps synchronously:

```php
$sink = $this->fakeAuditStreamSink();
$this->runAsEnvironment('env_prod', function () {
    $this->registerAuditStream('splunk');
    app(AuditLog::class)->record(AuditEvent::forUser('user.login', 'user_1'));
});
$this->pumpAuditStream($streamId);

$sink->assertSentTo('splunk');   // the event was delivered — no network
```
