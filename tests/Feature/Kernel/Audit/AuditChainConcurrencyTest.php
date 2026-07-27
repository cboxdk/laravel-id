<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotAppendToAuditChain;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * The append path is the one place in the platform where two requests race for the
 * same value — the next position in a per-(environment, scope) hash chain. The rest
 * of the audit suite is single-writer, which is exactly why a lost-append bug lived
 * here undetected: it only shows when appenders overlap.
 *
 * Real contention needs real processes against a server engine. Sqlite has no
 * row-level locking and a `:memory:` database is not even shared between
 * connections, so the first test skips there and runs when DB_CONNECTION=pgsql (or
 * mysql) points the suite at a server. The second test is engine-independent: it
 * injects the exact interleaving the race produces, so the regression stays covered
 * on the default sqlite run.
 */
it('loses no append when many processes contend on one chain', function (): void {
    $writers = 8;
    $perWriter = 100;

    // Resolve everything the children will need while there is still one process,
    // so a lazy singleton is not built concurrently by eight of them.
    app(AuditLog::class);

    // Commit RefreshDatabase's wrapping transaction: the children are separate
    // connections and would otherwise not see the schema this test runs against.
    // (Its teardown rollback then becomes a no-op, so the test clears up after
    // itself below.)
    DB::commit();

    // Drop the parent's socket next: a forked child inherits the file descriptor,
    // and two processes talking over one connection corrupts the protocol stream.
    DB::disconnect();

    $results = sys_get_temp_dir().'/audit-chain-'.bin2hex(random_bytes(8));
    mkdir($results);

    $pids = [];

    for ($writer = 0; $writer < $writers; $writer++) {
        $pid = pcntl_fork();

        expect($pid)->not->toBe(-1, 'could not fork an audit appender');

        if ($pid === 0) {
            $written = 0;
            $errors = [];

            for ($n = 0; $n < $perWriter; $n++) {
                try {
                    app(AuditLog::class)->record(AuditEvent::forSystem('concurrent.append'));
                    $written++;
                } catch (Throwable $e) {
                    $errors[] = $e::class.': '.$e->getMessage();
                }
            }

            file_put_contents(
                $results.'/'.$writer.'.json',
                (string) json_encode(['written' => $written, 'errors' => array_slice($errors, 0, 3)]),
            );

            // Leave without unwinding: PHPUnit's shutdown handlers would report the
            // child as a second test run and flush the parent's output buffers.
            posix_kill(posix_getpid(), SIGKILL);
        }

        $pids[] = $pid;
    }

    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }

    $written = 0;
    $errors = [];

    for ($writer = 0; $writer < $writers; $writer++) {
        $report = json_decode((string) file_get_contents($results.'/'.$writer.'.json'), true);

        expect($report)->toBeArray();

        $written += $report['written'];
        $errors = array_merge($errors, $report['errors']);
    }

    array_map('unlink', (array) glob($results.'/*'));
    rmdir($results);

    $expected = $writers * $perWriter;

    // Every append reported success...
    expect($errors)->toBe([])
        ->and($written)->toBe($expected);

    // ...every append is actually on disk, at its own position...
    $chain = DB::table('audit_logs')
        ->where('scope', '__system__')
        ->orderBy('sequence')
        ->pluck('sequence')
        ->all();

    expect($chain)->toHaveCount($expected)
        // Gapless: a hole is what tamper detection reads as a deletion.
        ->and($chain)->toBe(range(1, $expected));

    // ...and the hash linkage survived being written by eight processes at once.
    $verified = app(AuditLog::class)->verifyChain(null)->valid;

    DB::table('audit_logs')->delete();

    expect($verified)->toBeTrue();
})->skip(
    fn (): bool => DB::connection()->getDriverName() === 'sqlite' || ! function_exists('pcntl_fork'),
    'needs a server engine and pcntl: set DB_CONNECTION=pgsql (or mysql) to run it',
);

it('re-reads the head and keeps the entry when its position is taken mid-append', function (): void {
    $log = app(AuditLog::class);

    $log->record(AuditEvent::forSystem('first'));

    // Reproduce the interleaving a stale chain head produces: by the time this
    // append inserts, the position it computed has been claimed by someone else.
    // On PostgreSQL that is a blocked `FOR UPDATE` waking on the old head; here it
    // is injected directly, because sqlite cannot run a second writer.
    $raced = false;

    AuditEntry::creating(function () use (&$raced, $log): void {
        if ($raced) {
            return;
        }

        $raced = true;

        $log->record(AuditEvent::forSystem('competitor'));
    });

    // Before the fix this threw UniqueConstraintViolationException — DB::transaction's
    // `attempts` only retries SQLSTATE 40001, never a 23505 duplicate key — and every
    // caller that reports-and-continues turned that into a silent hole in the trail.
    $entry = $log->record(AuditEvent::forSystem('second'));

    expect($raced)->toBeTrue()
        ->and($entry->exists)->toBeTrue();

    $chain = DB::table('audit_logs')
        ->where('scope', '__system__')
        ->orderBy('sequence')
        ->pluck('sequence')
        ->all();

    expect($chain)->toBe(range(1, count($chain)))
        ->and($entry->sequence)->toBe(count($chain))
        ->and($log->verifyChain(null)->valid)->toBeTrue();
});

it('gives up loudly rather than dropping an entry it cannot place', function (): void {
    $log = app(AuditLog::class);

    $log->record(AuditEvent::forSystem('first'));

    // A competitor that takes the position on EVERY attempt, so the retry budget is
    // spent. The trail must not simply lose the entry: a hole reads as a deletion to
    // verifyChain(), so the caller has to be told.
    $injecting = false;

    AuditEntry::creating(function () use (&$injecting, $log): void {
        if ($injecting) {
            return;
        }

        $injecting = true;

        try {
            $log->record(AuditEvent::forSystem('competitor'));
        } finally {
            $injecting = false;
        }
    });

    expect(fn () => $log->record(AuditEvent::forSystem('second')))
        ->toThrow(CannotAppendToAuditChain::class);
});
