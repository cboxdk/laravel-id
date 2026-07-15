<?php

declare(strict_types=1);

use Cbox\Id\AuditStreaming\Models\AuditStreamDelivery;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\LaravelSiem\Enums\DeliveryStatus;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

// Isolation, not SSRF: keep registration offline-deterministic.
beforeEach(fn () => config(['siem.http.verify_url' => false]));

/**
 * @group isolation
 *
 * The big one: an env-A audit entry only ever produces outbox rows for env-A
 * streams, at BOTH the dispatch stage and the pump stage. A stream registered in
 * env-B receives nothing from an env-A event.
 */
it('writes an outbox row only for a stream in the recording environment', function (): void {
    // A stream in each environment.
    $streamA = $this->runAsEnvironment('env_a', fn () => $this->registerAuditStream('splunk-a'));
    $streamB = $this->runAsEnvironment('env_b', fn () => $this->registerAuditStream('splunk-b'));

    // Record an audit event in env_a.
    $this->runAsEnvironment('env_a', fn () => app(AuditLog::class)->record(
        AuditEvent::forSystem('config.changed'),
    ));

    // env_a's stream got exactly one delivery; env_b's stream got none.
    $inA = $this->runAsEnvironment('env_a', fn () => AuditStreamDelivery::query()
        ->where('stream_id', $streamA->stream->id)->count());
    $inB = $this->runAsEnvironment('env_b', fn () => AuditStreamDelivery::query()
        ->where('stream_id', $streamB->stream->id)->count());

    expect($inA)->toBe(1)
        ->and($inB)->toBe(0);

    // And the whole env_b outbox is empty — the env-A event never crossed over.
    $totalInB = $this->runAsEnvironment('env_b', fn () => AuditStreamDelivery::query()->count());
    expect($totalInB)->toBe(0);
});

/**
 * @group isolation
 *
 * The pump for an env-A stream, running inside the reconstructed env-A, never
 * loads or delivers an env-B delivery row.
 */
it('pumps only the recording environment and leaves other environments untouched', function (): void {
    $sink = $this->fakeAuditStreamSink();

    $streamA = $this->runAsEnvironment('env_a', fn () => $this->registerAuditStream('splunk-a'));
    $streamB = $this->runAsEnvironment('env_b', fn () => $this->registerAuditStream('splunk-b'));

    // An event in each environment ⇒ one pending outbox row per environment.
    $this->runAsEnvironment('env_a', fn () => app(AuditLog::class)->record(AuditEvent::forSystem('user.created')));
    $this->runAsEnvironment('env_b', fn () => app(AuditLog::class)->record(AuditEvent::forSystem('user.created')));

    // Pump ONLY env_a's stream (it reconstructs env_a internally).
    $this->pumpAuditStream($streamA->stream->id);

    // env_a delivered; env_b still pending and never seen by the sink.
    $aStatus = $this->runAsEnvironment('env_a', fn () => AuditStreamDelivery::query()
        ->where('stream_id', $streamA->stream->id)->value('status'));
    $bStatus = $this->runAsEnvironment('env_b', fn () => AuditStreamDelivery::query()
        ->where('stream_id', $streamB->stream->id)->value('status'));

    expect($aStatus)->toBe(DeliveryStatus::Delivered)
        ->and($bStatus)->toBe(DeliveryStatus::Pending)
        ->and($sink->records())->toHaveCount(1);
});

/**
 * @group isolation
 *
 * The cross-environment fan-out command enumerates every environment's streams
 * (under withoutScope) and dispatches a per-stream pump each; every job then
 * reconstructs and delivers inside its OWN environment. Nothing leaks across.
 */
it('fans the pump out across every environment via the command', function (): void {
    // Run dispatched jobs inline so the command's fan-out completes in-process.
    config(['queue.default' => 'sync']);
    $sink = $this->fakeAuditStreamSink();

    $streamA = $this->runAsEnvironment('env_a', fn () => $this->registerAuditStream('splunk-a'));
    $streamB = $this->runAsEnvironment('env_b', fn () => $this->registerAuditStream('splunk-b'));

    $this->runAsEnvironment('env_a', fn () => app(AuditLog::class)->record(AuditEvent::forSystem('user.created')));
    $this->runAsEnvironment('env_b', fn () => app(AuditLog::class)->record(AuditEvent::forSystem('user.created')));

    // One system step, no ambient environment — the command dispatches per stream.
    $this->pumpAuditStreams();

    $aStatus = $this->runAsEnvironment('env_a', fn () => AuditStreamDelivery::query()
        ->where('stream_id', $streamA->stream->id)->value('status'));
    $bStatus = $this->runAsEnvironment('env_b', fn () => AuditStreamDelivery::query()
        ->where('stream_id', $streamB->stream->id)->value('status'));

    // Both environments delivered — each inside its own reconstructed environment.
    expect($aStatus)->toBe(DeliveryStatus::Delivered)
        ->and($bStatus)->toBe(DeliveryStatus::Delivered)
        ->and($sink->records())->toHaveCount(2);
});

/**
 * @group isolation
 *
 * With no ambient environment (a bare queue worker), the env-owned models are
 * deny-by-default: the decorator sees no streams and writes nothing.
 */
it('is deny-by-default with no ambient environment', function (): void {
    $this->runAsEnvironment('env_a', fn () => $this->registerAuditStream('splunk-a'));

    // Clear the environment (as a worker with none would be) and record.
    $this->forgetEnvironment();

    app(AuditLog::class)->record(AuditEvent::forSystem('config.changed'));

    $total = $this->withoutEnvironmentScope(fn () => AuditStreamDelivery::query()->count());
    expect($total)->toBe(0);
});
