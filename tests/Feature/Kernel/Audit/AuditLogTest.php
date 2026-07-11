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
