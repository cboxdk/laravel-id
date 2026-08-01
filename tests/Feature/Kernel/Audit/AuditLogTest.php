<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('appends the first entry chained to genesis', function (): void {
    $entry = app(AuditLog::class)->record(AuditEvent::forSystem('platform.boot'));

    expect($entry->sequence)->toBe(1)
        ->and($entry->prev_hash)->toBe(str_repeat('0', 64))
        ->and($entry->hash)->toHaveLength(64);
});

it('increments sequence per scope and links each entry to the previous', function (): void {
    $log = app(AuditLog::class);

    $first = $log->record(AuditEvent::forSystem('a'));
    $second = $log->record(AuditEvent::forSystem('b'));

    expect($second->sequence)->toBe(2)
        ->and($second->prev_hash)->toBe($first->hash);
});

it('keeps a separate chain per scope', function (): void {
    $log = app(AuditLog::class);

    $log->record(new AuditEvent(action: 'x', organizationId: 'org_a'));
    $log->record(new AuditEvent(action: 'y', organizationId: 'org_b'));
    $secondForA = $log->record(new AuditEvent(action: 'z', organizationId: 'org_a'));

    expect($secondForA->sequence)->toBe(2); // org_a's own chain, unaffected by org_b
});

it('verifies an intact chain', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $log->record(AuditEvent::forSystem('b'));
    $log->record(AuditEvent::forSystem('c'));

    $result = $log->verifyChain(null);

    expect($result->valid)->toBeTrue()
        ->and($result->verifiedCount)->toBe(3)
        ->and($result->brokenAtSequence)->toBeNull();
});

/**
 * Every column that goes into the hash, one at a time.
 *
 * The trail's whole product claim is tamper-evidence, and eleven fields go into
 * `canonicalPayload()` — but only `action` and `environment_id` were ever proven to be
 * there. I removed the other eight in one edit and the entire Audit, AuditQuery,
 * AuditStreaming and Maintenance suites stayed green: 73 passed. So a refactor could drop
 * WHO acted, FROM WHERE, ON WHAT and WITH WHAT DETAIL out of the hash, and anyone with
 * database write access could rewrite all four while verifyChain() still answered "valid".
 *
 * A forged value has to DIFFER from the original, or the hash is unchanged and the test
 * proves nothing — hence the deliberately distinct values below.
 */
it('detects tampering with any hashed column', function (string $column, mixed $forged, int $breaksAt): void {
    $log = app(AuditLog::class);

    foreach (['a', 'b', 'c'] as $action) {
        $log->record(new AuditEvent(
            action: $action,
            actorType: ActorType::User,
            actorId: 'actor_original',
            targetType: 'user',
            targetId: 'target_original',
            context: ['reason' => 'original'],
            ip: '198.51.100.7',
        ));
    }

    DB::table('audit_logs')->where('scope', '__system__')->where('sequence', 2)->update([$column => $forged]);

    $result = $log->verifyChain(null);

    expect($result->valid)->toBeFalse("{$column} is not covered by the chain hash")
        ->and($result->brokenAtSequence)->toBe($breaksAt);
})->with([
    // Rewriting a field breaks the entry's OWN hash, so the break is at that entry.
    'action' => ['action', 'forged', 2],
    'organization_id' => ['organization_id', 'org_forged', 2],
    'actor_type' => ['actor_type', 'system', 2],
    'actor_id' => ['actor_id', 'actor_forged', 2],
    'target_type' => ['target_type', 'organization', 2],
    'target_id' => ['target_id', 'target_forged', 2],
    'context' => ['context', '{"reason":"forged"}', 2],
    'ip' => ['ip', '203.0.113.9', 2],
    'recorded_at' => ['recorded_at', '2020-01-01 00:00:00', 2],

    // These two identify the CHAIN, so rewriting one removes the row from the chain
    // being read rather than corrupting it in place. The break therefore surfaces at the
    // next entry, whose prev_hash no longer matches anything present — which is exactly
    // the property that makes a row unmovable between environments and scopes.
    'environment_id' => ['environment_id', 'env_forged', 3],
    'scope' => ['scope', 'forged_scope', 3],
]);

it('detects a tampered entry', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $log->record(AuditEvent::forSystem('b'));
    $log->record(AuditEvent::forSystem('c'));

    // Rewrite content directly, without recomputing the chain hash.
    DB::table('audit_logs')->where('scope', '__system__')->where('sequence', 2)->update(['action' => 'forged']);

    $result = $log->verifyChain(null);

    expect($result->valid)->toBeFalse()
        ->and($result->brokenAtSequence)->toBe(2);
});

it('detects a deleted entry as a chain break', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $log->record(AuditEvent::forSystem('b'));
    $log->record(AuditEvent::forSystem('c'));

    DB::table('audit_logs')->where('scope', '__system__')->where('sequence', 2)->delete();

    $result = $log->verifyChain(null);

    expect($result->valid)->toBeFalse()
        ->and($result->brokenAtSequence)->toBe(3);
});

it('records actor type, id and context', function (): void {
    $entry = app(AuditLog::class)->record(
        AuditEvent::forUser('user.login', 'user_1', 'org_a', ['method' => 'password']),
    );

    expect($entry->actor_type)->toBe(ActorType::User)
        ->and($entry->actor_id)->toBe('user_1')
        ->and($entry->organization_id)->toBe('org_a')
        ->and($entry->context)->toBe(['method' => 'password']);
});
