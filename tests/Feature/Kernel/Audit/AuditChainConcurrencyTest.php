<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotAppendToAuditChain;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
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

/**
 * The MariaDB genesis race, in the two properties that fix it. Both run on the
 * default sqlite suite; the engine that actually exhibited the bug is exercised by
 * the forking test above, which is green on MariaDB 11.8.8 only with these in place.
 */
it('retries a serialisation failure instead of handing it to the caller', function (): void {
    $log = app(AuditLog::class);

    // Commit RefreshDatabase's wrapping transaction so the append runs the way it
    // runs in a request — owning its own outermost transaction. A concurrency error
    // raised INSIDE a caller's transaction is deliberately not retried: the engine
    // has already rolled that transaction back, Laravel converts it to a
    // DeadlockException and unwinds, and retrying inside a dead transaction would
    // only produce a second failure. (Its teardown rollback then becomes a no-op, so
    // this test clears up after itself below.)
    DB::commit();

    $log->record(AuditEvent::forSystem('first'));

    // Eight writers contending on one empty chain do not produce ONE deadlock, they
    // produce a pile-up: MariaDB picked a victim, the victim retried straight into the
    // next round, and Laravel's private budget of three attempts ran out while the
    // chain was still being opened. Three consecutive victims here is that shape.
    $deadlocks = 0;

    AuditEntry::creating(function () use (&$deadlocks): void {
        if ($deadlocks >= 3) {
            return;
        }

        $deadlocks++;

        throw new QueryException(
            'testing',
            'insert into "audit_logs" ("sequence") values (?)',
            [2],
            new PDOException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction'),
        );
    });

    // Before the fix this reached the caller: `DB::transaction(…, attempts: 3)` gave
    // up after the third victim and record() only caught duplicate keys, so a loud
    // QueryException came out of a call site that reports-and-continues.
    $entry = $log->record(AuditEvent::forSystem('second'));

    $verified = $log->verifyChain(null)->valid;

    DB::table('audit_logs')->delete();

    expect($deadlocks)->toBe(3)
        ->and($entry->sequence)->toBe(2)
        ->and($verified)->toBeTrue();
});

it('locks the chain anchor by primary key, and locks nothing at all on an empty chain', function (): void {
    $log = app(AuditLog::class);

    /** @var list<string> $sql */
    $sql = [];

    DB::listen(function (QueryExecuted $query) use (&$sql): void {
        $sql[] = $query->sql;
    });

    // Identifier quoting is per grammar (`"` on sqlite/Postgres, backticks on
    // MySQL/MariaDB) and this assertion is about the predicate, not the dialect.
    $bare = static fn (string $statement): string => str_replace(['"', '`'], '', $statement);

    // A read addressed by primary key is the ONLY lock shape that cannot take a gap
    // lock, which is what made eight MariaDB writers deadlock on an empty chain. Sqlite
    // compiles no `for update` clause at all, so the assertion is on the statement the
    // lock rides on — its predicate is the whole point, and it is engine-independent.
    $anchorLock = static fn (string $statement): bool => str_contains($bare($statement), 'select id from audit_logs where audit_logs.id = ?');

    $log->record(AuditEvent::forSystem('genesis'));

    // Nothing exists to serialise on yet, so nothing is locked: the unique key
    // decides the race and record() absorbs the loser's duplicate key.
    expect(array_filter($sql, $anchorLock))->toBe([]);

    $sql = [];

    $log->record(AuditEvent::forSystem('second'));

    expect(array_filter($sql, $anchorLock))->toHaveCount(1);

    // ...and it is taken BEFORE the insert, not alongside it.
    $order = array_values(array_filter(
        $sql,
        static fn (string $statement): bool => $anchorLock($statement) || str_starts_with($bare($statement), 'insert into audit_logs'),
    ));

    expect($order)->toHaveCount(2)
        ->and($anchorLock($order[0]))->toBeTrue();
});
