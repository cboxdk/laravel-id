<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Chain\CboxIdEntryCodec;
use Cbox\Id\Kernel\Audit\Checkpointer;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\DatabaseAuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * BYTE-IDENTICAL COMPATIBILITY WITH THE PRE-EXTRACTION AUDIT CHAIN.
 *
 * tests/Fixtures/audit/golden-vectors.json was written by laravel-id's own
 * DatabaseAuditLog before the chain moved into cboxdk/laravel-audit-chain (see its
 * `_provenance`; the generator was removed in the same change as the implementation it
 * recorded, because regenerating from the new code would only prove it agrees with
 * itself). It holds the rows exactly as stored — including the signed checkpoints
 * and the signing keys that signed them — and the inputs that produced them.
 *
 * Every deployment's existing `audit_logs` must keep verifying after an upgrade, and every
 * entry recorded after it must extend those chains with hashes the old code would have
 * computed. These tests hold any implementation to both, from the stored bytes:
 *
 *   1. verification of the STORED rows answers exactly what it answered before — valid
 *      chains stay valid with the same counts, and the two pre-existing refusals (the
 *      platform chain verified from outside any environment) stay refusals;
 *   2. tampering with the stored rows is still caught;
 *   3. replaying the recorded INPUTS produces the same sequences, prev-hashes, hashes,
 *      stored column values, checkpoint claims and Checkpointer outcomes;
 *   4. the canonical bytes that go into each hash are pinned, not just the digest.
 */

/**
 * @return array{
 *     crypto_master_key: string,
 *     operations: list<array<string, mixed>>,
 *     verifications: list<array<string, mixed>>,
 *     tables: array{audit_logs: list<array<string, mixed>>, audit_checkpoints: list<array<string, mixed>>, signing_keys: list<array<string, mixed>>}
 * }
 */
function auditGoldenFixture(): array
{
    /** @var array{crypto_master_key: string, operations: list<array<string, mixed>>, verifications: list<array<string, mixed>>, tables: array{audit_logs: list<array<string, mixed>>, audit_checkpoints: list<array<string, mixed>>, signing_keys: list<array<string, mixed>>}} $fixture */
    $fixture = json_decode((string) file_get_contents(dirname(__DIR__, 4).'/Fixtures/audit/golden-vectors.json'), true, flags: JSON_THROW_ON_ERROR);

    return $fixture;
}

/**
 * Use the fixture's master key, so the exported signing-key rows open and sign exactly
 * as they did when the fixture was written.
 */
function useGoldenCrypto(string $masterKey): void
{
    config(['cbox-id.crypto.key' => $masterKey]);

    foreach ([SecretBox::class, KeyManager::class, TokenSigner::class, AuditLog::class, Checkpointer::class] as $abstract) {
        app()->forgetInstance($abstract);
    }
}

/**
 * @param  list<array<string, mixed>>  $rows
 */
function insertGoldenRows(string $table, array $rows): void
{
    foreach ($rows as $row) {
        DB::table($table)->insert($row);
    }
}

function actAsGoldenEnvironment(?string $environment): void
{
    app(EnvironmentContext::class)->set($environment === null ? null : GenericEnvironment::of($environment));
}

/**
 * The claims a checkpoint JWT carries, in signing order, minus the per-signature `jti`.
 *
 * @return array<string, mixed>
 */
function goldenCheckpointClaims(string $jwt): array
{
    $segments = explode('.', $jwt);

    expect($segments)->toHaveCount(3);

    /** @var array<string, mixed> $claims */
    $claims = json_decode((string) base64_decode(strtr($segments[1], '-_', '+/')), true, flags: JSON_THROW_ON_ERROR);

    unset($claims['jti']);

    return $claims;
}

/**
 * A JSON document re-encoded with its keys sorted at every depth, so two engines'
 * spellings of the same value compare equal.
 */
function goldenSortedJson(string $json): string
{
    $sort = static function (mixed $value) use (&$sort): mixed {
        if (! is_array($value)) {
            return $value;
        }

        ksort($value);

        return array_map($sort, $value);
    };

    return (string) json_encode($sort(json_decode($json, true, flags: JSON_THROW_ON_ERROR)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

/**
 * The exact bytes hashed for a stored entry.
 *
 * Before the extraction this read the private DatabaseAuditLog::canonicalPayload(); the
 * canonical form now lives in CboxIdEntryCodec, and the fixture's `canonical` values —
 * written by that private method — are what it is held to.
 */
function goldenCanonicalBytes(AuditEntry $entry): string
{
    return (new CboxIdEntryCodec)->canonicalize($entry);
}

it('verifies the stored golden rows exactly as the pre-extraction implementation did', function (): void {
    $fixture = auditGoldenFixture();
    useGoldenCrypto($fixture['crypto_master_key']);

    insertGoldenRows('signing_keys', $fixture['tables']['signing_keys']);
    insertGoldenRows('audit_logs', $fixture['tables']['audit_logs']);
    insertGoldenRows('audit_checkpoints', $fixture['tables']['audit_checkpoints']);

    expect($fixture['verifications'])->not->toBeEmpty();

    foreach ($fixture['verifications'] as $expected) {
        $environment = $expected['verified_as'] === 'no_environment' ? null : $expected['environment_id'];
        $organizationId = $expected['scope'] === DatabaseAuditLog::SYSTEM_SCOPE ? null : $expected['scope'];

        actAsGoldenEnvironment(is_string($environment) ? $environment : null);

        $result = app(AuditLog::class)->verifyChain(is_string($organizationId) ? $organizationId : null);
        $label = $expected['environment_id'].'/'.$expected['scope'].' as '.$expected['verified_as'];

        expect($result->valid)->toBe($expected['valid'], $label)
            ->and($result->verifiedCount)->toBe($expected['verified_count'], $label)
            ->and($result->brokenAtSequence)->toBe($expected['broken_at_sequence'], $label)
            ->and($result->reason)->toBe($expected['reason'], $label)
            ->and(app(AuditLog::class)->headSequence(is_string($organizationId) ? $organizationId : null))->toBe($expected['head_sequence'], $label);

        // A window that starts mid-chain picks its prev-hash up from the stored entry
        // before it, so this also proves the stored linkage, not just the whole walk.
        if ($expected['valid'] === true && $expected['head_sequence'] > 1) {
            $window = app(AuditLog::class)->verifyChain(is_string($organizationId) ? $organizationId : null, fromSequence: 2);

            expect($window->valid)->toBeTrue($label.' (window from 2)')
                ->and($window->verifiedCount)->toBe($expected['head_sequence'] - 1, $label.' (window from 2)');
        }
    }
});

it('still catches tampering with the stored golden rows', function (string $column, mixed $forged): void {
    $fixture = auditGoldenFixture();
    useGoldenCrypto($fixture['crypto_master_key']);

    insertGoldenRows('signing_keys', $fixture['tables']['signing_keys']);
    insertGoldenRows('audit_logs', $fixture['tables']['audit_logs']);

    $environment = '01J8ZK3V9Q4XW5T6Y7R8S9A0BC';
    $scope = '01J8ZM0RGA0000000000000001';

    actAsGoldenEnvironment($environment);

    expect(app(AuditLog::class)->verifyChain($scope)->valid)->toBeTrue();

    DB::table('audit_logs')->where('environment_id', $environment)->where('scope', $scope)->where('sequence', 3)->update([$column => $forged]);

    $result = app(AuditLog::class)->verifyChain($scope);

    expect($result->valid)->toBeFalse("{$column} is not covered by the chain hash")
        ->and($result->brokenAtSequence)->toBe(3);
})->with([
    'action' => ['action', 'user.forged'],
    'actor_type' => ['actor_type', 'system'],
    'actor_id' => ['actor_id', 'usr_forged'],
    'organization_id' => ['organization_id', '01J8ZM0RGB0000000000000002'],
    'target_type' => ['target_type', 'session'],
    'target_id' => ['target_id', 'usr_forged'],
    // Same keys, one unicode character changed.
    'context' => ['context', '{"city":"京都","emoji":"🔐👩‍💻","name":"Søren Ærø Åberg","newline":"line1\nline2\ttab","nul":"a\u0000b","quote":"she said \"hi\"","rtl":"مرحبا"}'],
    'ip' => ['ip', '192.0.2.1'],
    'recorded_at' => ['recorded_at', '2026-09-01 10:09:08'],
    'prev_hash' => ['prev_hash', str_repeat('a', 64)],
    'hash' => ['hash', str_repeat('b', 64)],
]);

it('re-records the golden inputs to byte-identical rows, hashes and checkpoints', function (): void {
    $fixture = auditGoldenFixture();
    useGoldenCrypto($fixture['crypto_master_key']);

    // Only the KEYS carry over — the chains are rebuilt from the recorded inputs.
    insertGoldenRows('signing_keys', $fixture['tables']['signing_keys']);

    $storedCheckpoints = $fixture['tables']['audit_checkpoints'];

    foreach ($fixture['operations'] as $index => $operation) {
        $label = 'operation #'.$index.' ('.$operation['op'].')';
        $this->travelTo(Carbon::parse((string) $operation['at']));

        if ($operation['op'] === 'record') {
            actAsGoldenEnvironment(is_string($operation['environment']) ? $operation['environment'] : null);

            /** @var array{action: string, actor_type: string, actor_id: string|null, organization_id: string|null, target_type: string|null, target_id: string|null, context_php: string, ip: string|null} $input */
            $input = $operation['event'];
            /** @var array<string, mixed> $context */
            $context = unserialize($input['context_php'], ['allowed_classes' => false]);

            $entry = app(AuditLog::class)->record(new AuditEvent(
                action: $input['action'],
                actorType: ActorType::from($input['actor_type']),
                actorId: $input['actor_id'],
                organizationId: $input['organization_id'],
                targetType: $input['target_type'],
                targetId: $input['target_id'],
                context: $context,
                ip: $input['ip'],
            ));

            /** @var array{environment_id: string, scope: string, sequence: int, prev_hash: string, hash: string, canonical: string} $expect */
            $expect = $operation['expect'];

            expect($entry->environment_id)->toBe($expect['environment_id'], $label)
                ->and($entry->scope)->toBe($expect['scope'], $label)
                ->and($entry->sequence)->toBe($expect['sequence'], $label)
                ->and($entry->prev_hash)->toBe($expect['prev_hash'], $label)
                ->and($entry->hash)->toBe($expect['hash'], $label)
                ->and(goldenCanonicalBytes($entry))->toBe($expect['canonical'], $label);

            continue;
        }

        if ($operation['op'] === 'checkpoint') {
            actAsGoldenEnvironment(is_string($operation['environment']) ? $operation['environment'] : null);
            $organizationId = is_string($operation['organization_id']) ? $operation['organization_id'] : null;

            /** @var array<string, mixed> $expect */
            $expect = $operation['expect'];

            if (isset($expect['throws'])) {
                // In a savepoint: on PostgreSQL a failed statement aborts the whole
                // enclosing transaction, and this refusal is expected.
                expect(fn () => DB::transaction(fn () => app(AuditLog::class)->checkpoint($organizationId)))
                    ->toThrow((string) $expect['throws']);

                continue;
            }

            $checkpoint = app(AuditLog::class)->checkpoint($organizationId);

            expect($checkpoint->environment_id)->toBe($expect['environment_id'], $label)
                ->and($checkpoint->scope)->toBe($expect['scope'], $label)
                ->and($checkpoint->organization_id)->toBe($expect['organization_id'], $label)
                ->and($checkpoint->up_to_sequence)->toBe($expect['up_to_sequence'], $label)
                ->and($checkpoint->root_hash)->toBe($expect['root_hash'], $label);

            $claims = goldenCheckpointClaims($checkpoint->signature);

            expect(array_keys($claims))->toBe(array_values(array_diff((array) $expect['claim_order'], ['jti'])), $label);

            $stored = array_values(array_filter($storedCheckpoints, static fn (array $row): bool => $row['environment_id'] === $expect['environment_id']
                && $row['scope'] === $expect['scope']
                && (int) $row['up_to_sequence'] === $expect['up_to_sequence']));

            expect($stored)->toHaveCount(1, $label)
                ->and($claims)->toBe(goldenCheckpointClaims((string) $stored[0]['signature']), $label);

            continue;
        }

        // checkpoint_all: the Checkpointer re-enters every chain's environment itself.
        actAsGoldenEnvironment('env_test');

        $outcomes = array_map(static fn ($outcome): array => [
            'environment_id' => $outcome->environmentId,
            'scope' => $outcome->scope,
            'head_sequence' => $outcome->headSequence,
            'checkpointed_sequence' => $outcome->checkpointedSequence,
            'signed' => $outcome->wasSigned(),
            'skipped' => $outcome->skippedReason,
            'failed' => $outcome->failureReason,
        ], app(Checkpointer::class)->checkpointAll());

        // The pass walks chains in `ORDER BY environment_id, scope`, which follows the
        // engine's collation (MySQL sorts `__platform__` first, SQLite last), so the
        // outcomes are compared as a set.
        $byChain = static fn (array $rows): array => collect($rows)
            ->sortBy(static fn (array $row): string => $row['environment_id']."\0".$row['scope'])
            ->values()->all();

        expect($byChain($outcomes))->toBe($byChain((array) $operation['expect']), $label);
    }

    // And the tables as a whole: every stored column but the random row id. On SQLite
    // (where the fixture was written) that includes the raw JSON text of `context`, byte
    // for byte. A server engine's JSON column may re-serialise it — MySQL reorders keys
    // and respaces — which the hash absorbs by canonicalising what it reads, so there
    // `context` is compared as the JSON value it holds.
    $raw = DB::connection()->getDriverName() === 'sqlite';

    $comparable = static fn (array $rows, array $drop): array => array_map(
        static function (array $row) use ($drop, $raw): array {
            foreach ($drop as $column) {
                unset($row[$column]);
            }

            if (! $raw && array_key_exists('context', $row)) {
                $row['context'] = goldenSortedJson((string) $row['context']);
            }

            foreach (['sequence', 'up_to_sequence'] as $integer) {
                if (array_key_exists($integer, $row)) {
                    $row[$integer] = (int) $row[$integer];
                }
            }

            ksort($row);

            return $row;
        },
        $rows,
    );

    $order = static fn (array $rows): array => collect($rows)
        ->sortBy(static fn (array $row): string => $row['environment_id'].'|'.$row['scope'].'|'.str_pad((string) ($row['sequence'] ?? $row['up_to_sequence']), 10, '0', STR_PAD_LEFT).'|'.($row['created_at'] ?? ''))
        ->values()->all();

    $logs = DB::table('audit_logs')->get()->map(static fn (object $row): array => (array) $row)->all();

    expect($comparable($order($logs), ['id']))
        ->toBe($comparable($order($fixture['tables']['audit_logs']), ['id']));

    $checkpoints = DB::table('audit_checkpoints')->get()->map(static fn (object $row): array => (array) $row)->all();

    $withClaims = static fn (array $rows): array => array_map(static function (array $row): array {
        $row['signature'] = goldenCheckpointClaims((string) $row['signature']);

        return $row;
    }, $rows);

    expect($comparable($withClaims($order($checkpoints)), ['id']))
        ->toBe($comparable($withClaims($order($fixture['tables']['audit_checkpoints'])), ['id']));
});

it('pins the canonical bytes hashed for every stored golden entry', function (): void {
    $fixture = auditGoldenFixture();

    insertGoldenRows('audit_logs', $fixture['tables']['audit_logs']);

    $records = array_values(array_filter($fixture['operations'], static fn (array $op): bool => $op['op'] === 'record'));

    expect($records)->toHaveCount(count($fixture['tables']['audit_logs']));

    foreach ($records as $operation) {
        /** @var array{environment_id: string, scope: string, sequence: int, prev_hash: string, hash: string, canonical: string} $expect */
        $expect = $operation['expect'];

        $entry = AuditEntry::query()->withoutGlobalScopes()
            ->where('environment_id', $expect['environment_id'])
            ->where('scope', $expect['scope'])
            ->where('sequence', $expect['sequence'])
            ->firstOrFail();

        $bytes = goldenCanonicalBytes($entry);

        // Read back from the STORED row — the verification path — and still the same
        // bytes and the same digest the writer produced.
        expect($bytes)->toBe($expect['canonical'])
            ->and(hash('sha256', $bytes.$entry->prev_hash))->toBe($expect['hash'])
            ->and($entry->hash)->toBe($expect['hash']);
    }
});
