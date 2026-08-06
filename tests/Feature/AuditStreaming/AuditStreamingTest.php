<?php

declare(strict_types=1);

use Cbox\Id\AuditStreaming\Models\AuditStream;
use Cbox\Id\AuditStreaming\Models\AuditStreamDelivery;
use Cbox\Id\AuditStreaming\StreamingAuditLog;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Tests\Fixtures\ContextStampingAuditLog;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['siem.http.verify_url' => false]));

/**
 * @param  list<string>  $records
 * @return array<string, mixed>
 */
function decodeSplunkEvent(array $records): array
{
    expect($records)->toHaveCount(1);
    $decoded = json_decode($records[0], true);
    expect($decoded)->toBeArray();

    return $decoded['event'];
}

it('delivers an audit entry end-to-end carrying the chain hash, sequence and prev_hash', function (): void {
    $sink = $this->fakeAuditStreamSink();
    $this->registerAuditStream('splunk');

    $entry = app(AuditLog::class)->record(AuditEvent::forUser('user.login', 'user_42'));

    $this->pumpAuditStream(
        AuditStreamDelivery::query()->value('stream_id'),
    );

    $event = decodeSplunkEvent($sink->records());

    // The dedup/idempotency key is the entry hash.
    expect($event['id'])->toBe($entry->hash);
    // Chain-continuity fields the customer SIEM verifies against.
    expect($event['context']['sequence'])->toBe($entry->sequence)
        ->and($event['context']['hash'])->toBe($entry->hash)
        ->and($event['context']['prev_hash'])->toBe($entry->prev_hash)
        ->and($event['action'])->toBe('user.login')
        ->and($event['actor'])->toBe(['type' => 'user', 'id' => 'user_42']);
});

it('uses the entry hash as the SiemEvent dedup id', function (): void {
    $sink = $this->fakeAuditStreamSink();
    $this->registerAuditStream('splunk');

    $entry = app(AuditLog::class)->record(AuditEvent::forSystem('config.changed'));
    $this->pumpAuditStream(AuditStreamDelivery::query()->value('stream_id'));

    expect(decodeSplunkEvent($sink->records())['id'])->toBe($entry->hash);
});

it('rolls back both the audit entry and the outbox row when the caller transaction rolls back', function (): void {
    $this->registerAuditStream('splunk');

    try {
        DB::transaction(function (): void {
            app(AuditLog::class)->record(AuditEvent::forSystem('config.changed'));

            throw new RuntimeException('caller aborts');
        });
    } catch (RuntimeException) {
        // expected
    }

    // Transactional outbox: neither the entry nor an orphan delivery survives.
    expect(AuditEntry::query()->count())->toBe(0)
        ->and(AuditStreamDelivery::query()->count())->toBe(0);
});

it('records via the inner log and dispatches nothing when no stream is configured (deny-by-default)', function (): void {
    $sink = $this->fakeAuditStreamSink();

    // No stream registered.
    $entry = app(AuditLog::class)->record(AuditEvent::forSystem('config.changed'));

    // The entry was still recorded and the chain verifies.
    expect(AuditEntry::query()->count())->toBe(1)
        ->and($entry->sequence)->toBe(1);
    expect(app(AuditLog::class)->verifyChain()->valid)->toBeTrue();

    // Nothing was streamed.
    expect(AuditStreamDelivery::query()->count())->toBe(0);
    $sink->assertNothingSent();
});

it('is bound as a decorator over the framework audit log', function (): void {
    expect(app(AuditLog::class))->toBeInstanceOf(StreamingAuditLog::class);
});

it('forces the engine models to the environment-owned subclasses (isolation invariant)', function (): void {
    // The entire isolation guarantee rests on the engine querying the env-owned
    // models. If a change ever stops the provider forcing these, streaming would
    // silently use the unscoped base models — so lock the wiring down.
    expect(config('siem.models.log_stream'))->toBe(AuditStream::class)
        ->and(config('siem.models.stream_delivery'))->toBe(AuditStreamDelivery::class)
        ->and(config('siem.schedule.enabled'))->toBeFalse();
});

it('composes with another audit-log decorator and keeps the chain intact', function (): void {
    // Bind a host-style decorator OUTSIDE the streaming one (as the app's
    // impersonation decorator is), stamping a context key.
    app()->extend(AuditLog::class, fn (AuditLog $inner, Application $app): AuditLog => new ContextStampingAuditLog(
        $inner,
        ['impersonated_by' => 'operator_9'],
    ));

    $sink = $this->fakeAuditStreamSink();
    $this->registerAuditStream('splunk');

    app(AuditLog::class)->record(AuditEvent::forUser('user.updated', 'user_1'));
    $this->pumpAuditStream(AuditStreamDelivery::query()->value('stream_id'));

    // The outer decorator's stamp flowed through the streaming decorator to the SIEM.
    $event = decodeSplunkEvent($sink->records());
    expect($event['context']['impersonated_by'])->toBe('operator_9');

    // And the underlying chain still verifies (streaming did not disturb recording).
    expect(app(AuditLog::class)->verifyChain(null)->valid)->toBeTrue();
});
