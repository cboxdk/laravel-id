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

/**
 * The provisioning outbox, which had the same hazard as the two above and no test.
 *
 * `pending` and `failed` are live work: `OutboxProvisioningService::retryPending()`
 * selects on exactly those two statuses, so deleting one silently drops a user
 * create/update/deactivate that a downstream SaaS is still owed. The predicate's own
 * comment says this. Nothing asserted it — and a comment is not a control, which is the
 * lesson this file's two sibling tests already encode for `events` and
 * `webhook_deliveries`.
 *
 * All four statuses, because the assertion that matters is WHICH TWO survive: a
 * predicate that deleted everything and one that deleted nothing both satisfy a bare
 * count.
 */
it('never deletes a provisioning operation the outbox still owes', function (): void {
    $rows = [];

    foreach (['pending', 'delivered', 'failed', 'exhausted'] as $status) {
        $rows[] = [
            'id' => (string) Str::ulid(),
            'environment_id' => (string) Str::ulid(),
            'connection_id' => (string) Str::ulid(),
            'user_id' => 'user_1',
            'type' => 'user.upsert',
            'payload' => '{}',
            'status' => $status,
            'created_at' => now()->subYear(),
            'updated_at' => now()->subYear(),
        ];
    }

    DB::table('provisioning_operations')->insert($rows);

    expect(app(Pruner::class)->prune(PrunableTable::ProvisioningOperations)->deleted)->toBe(2)
        ->and(DB::table('provisioning_operations')->pluck('status')->sort()->values()->all())
        ->toBe(['failed', 'pending']);
});

/**
 * Every table whose deadness depends on a STATUS has a test naming which statuses live.
 *
 * Three of the ten prunable tables decide by status rather than by a timestamp alone,
 * and each is a place where getting the predicate wrong deletes work the platform still
 * owes somebody — an undelivered event, an unretried webhook, an unsynced user. Two had
 * a test and the third did not, and the third was the one whose comment described the
 * danger most explicitly.
 *
 * Checked from the SOURCE of the enum rather than from a list here, so a new table with
 * a status predicate cannot be added without this failing.
 */
it('tests the live-work predicate of every status-driven prunable table', function (): void {
    $source = (string) file_get_contents(dirname(__DIR__, 3).'/src/Maintenance/Enums/PrunableTable.php');
    $tests = (string) file_get_contents(__FILE__);

    // ANCHORED ON deadRows(). The enum states the same `self::X =>` arms in several
    // methods, so searching the whole file finds whichever came first — for every case
    // that was `keyColumn()`, whose arms contain no predicate at all, and the sweep
    // matched nothing. The floor below is what said so rather than the assertion.
    $start = mb_strpos($source, 'public function deadRows(');
    expect($start)->not->toBeFalse('deadRows() was not found — this guard is reading the wrong file');

    $deadRows = mb_substr($source, (int) $start);

    /** @var list<string> $statusDriven */
    $statusDriven = [];

    foreach (PrunableTable::cases() as $table) {
        $at = mb_strpos($deadRows, 'self::'.$table->name);

        if ($at === false) {
            continue;
        }

        // To the next arm, so one case's predicate cannot be credited to its neighbour.
        $rest = mb_substr($deadRows, $at + 1);
        $next = mb_strpos($rest, "\n            self::");
        $body = $next === false ? $rest : mb_substr($rest, 0, $next);

        if (str_contains($body, "whereIn('status'")) {
            $statusDriven[] = $table->name;
        }
    }

    expect(count($statusDriven))->toBeGreaterThan(1, 'the predicate sweep found almost nothing — it is reading the wrong file');

    $untested = array_values(array_filter(
        $statusDriven,
        fn (string $name): bool => ! str_contains($tests, 'PrunableTable::'.$name),
    ));

    expect($untested)->toBe([], 'status-driven prunable tables with no live-work test: '.implode(', ', $untested));
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
