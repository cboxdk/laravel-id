<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Maintenance\Enums\PrunableTable;
use Cbox\Id\Maintenance\Pruner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/** Insert a dpop_proofs row that expired `$daysAgo` days ago. */
function prunableProof(int $daysAgo): string
{
    $id = (string) Str::ulid();

    DB::table('dpop_proofs')->insert([
        'id' => $id,
        'jkt' => 'jkt-'.$id,
        'jti' => 'jti-'.$id,
        'expires_at' => now()->subDays($daysAgo),
        'created_at' => now()->subDays($daysAgo),
        'updated_at' => now()->subDays($daysAgo),
    ]);

    return $id;
}

it('deletes rows past their retention and leaves the rest alone', function (): void {
    $stale = prunableProof(5);
    $fresh = prunableProof(0);

    $outcome = app(Pruner::class)->prune(PrunableTable::DpopProofs);

    expect($outcome->deleted)->toBe(1)
        ->and($outcome->retentionDays)->toBe(1)
        ->and(DB::table('dpop_proofs')->where('id', $stale)->exists())->toBeFalse()
        ->and(DB::table('dpop_proofs')->where('id', $fresh)->exists())->toBeTrue();
});

it('deletes in chunks, so a first sweep of a never-pruned table is bounded', function (): void {
    foreach (range(1, 7) as $ignored) {
        prunableProof(5);
    }

    // A chunk smaller than the backlog forces the loop to go round more than once;
    // the point is that it terminates having deleted everything, not just one page.
    expect(app(Pruner::class)->prune(PrunableTable::DpopProofs, chunk: 2)->deleted)->toBe(7)
        ->and(DB::table('dpop_proofs')->count())->toBe(0);
});

it('counts without deleting on a dry run', function (): void {
    prunableProof(5);

    $outcome = app(Pruner::class)->prune(PrunableTable::DpopProofs, dryRun: true);

    expect($outcome->deleted)->toBe(1)
        ->and(DB::table('dpop_proofs')->count())->toBe(1);
});

it('never deletes an outbox event the relay has not dispatched, however old', function (): void {
    DB::table('events')->insert([
        ['id' => (string) Str::ulid(), 'type' => 'user.created', 'payload' => '{}', 'occurred_at' => now()->subYear(), 'dispatched_at' => null],
        ['id' => (string) Str::ulid(), 'type' => 'user.created', 'payload' => '{}', 'occurred_at' => now()->subYear(), 'dispatched_at' => now()->subYear()],
    ]);

    expect(app(Pruner::class)->prune(PrunableTable::Events)->deleted)->toBe(1)
        ->and(DB::table('events')->whereNull('dispatched_at')->count())->toBe(1);
});

it('never deletes a webhook delivery that is still owed a retry', function (): void {
    $rows = [];

    foreach (['pending', 'failed', 'delivered', 'exhausted'] as $status) {
        $rows[] = [
            'id' => (string) Str::ulid(),
            'environment_id' => (string) Str::ulid(),
            'endpoint_id' => (string) Str::ulid(),
            'event_type' => 'user.created',
            'payload' => '{}',
            'status' => $status,
            'created_at' => now()->subYear(),
            'updated_at' => now()->subYear(),
        ];
    }

    DB::table('webhook_deliveries')->insert($rows);

    expect(app(Pruner::class)->prune(PrunableTable::WebhookDeliveries)->deleted)->toBe(2)
        ->and(DB::table('webhook_deliveries')->pluck('status')->sort()->values()->all())
        ->toBe(['failed', 'pending']);
});

it('leaves the hash-chained audit trail verifiable, because it never touches it', function (): void {
    $audit = app(AuditLog::class);

    foreach (range(1, 3) as $ignored) {
        $audit->record(new AuditEvent(action: 'test.event', actorType: ActorType::System));
    }

    // Retention 0 everywhere: even so the trail must be untouched, because it is not
    // a table the sweep knows about. (The entries are deliberately NOT back-dated —
    // `recorded_at` is inside the content hash, so ageing them here would itself be
    // the tampering the chain exists to detect.)
    config(['cbox-id.prune.retention_days' => array_fill_keys(
        array_map(static fn (PrunableTable $table): string => $table->value, PrunableTable::cases()),
        0,
    )]);

    app(Pruner::class)->pruneAll();

    expect(DB::table('audit_logs')->count())->toBe(3)
        ->and($audit->verifyChain()->valid)->toBeTrue();

    // And it is not merely absent by accident — it is not a prunable table at all.
    expect(array_map(
        static fn (PrunableTable $table): string => $table->value,
        PrunableTable::cases(),
    ))->not->toContain('audit_logs');
});

it('skips a table whose retention the operator turned off', function (): void {
    prunableProof(5);

    config(['cbox-id.prune.retention_days.dpop_proofs' => null]);

    $outcome = app(Pruner::class)->prune(PrunableTable::DpopProofs);

    expect($outcome->wasSkipped())->toBeTrue()
        ->and($outcome->deleted)->toBe(0)
        ->and(DB::table('dpop_proofs')->count())->toBe(1);
});

it('honours a configured retention window', function (): void {
    prunableProof(5);

    config(['cbox-id.prune.retention_days.dpop_proofs' => 30]);

    expect(app(Pruner::class)->prune(PrunableTable::DpopProofs)->deleted)->toBe(0);
});

it('sweeps every table from the command and reports what it removed', function (): void {
    prunableProof(5);

    $this->artisan('cbox-id:prune')
        ->expectsOutputToContain('Deleted 1 row(s).')
        ->expectsOutputToContain('audit_logs is never pruned')
        ->assertSuccessful();

    expect(DB::table('dpop_proofs')->count())->toBe(0);
});

it('refuses an unknown table rather than silently sweeping everything', function (): void {
    $this->artisan('cbox-id:prune --table=users')->assertFailed();
});
