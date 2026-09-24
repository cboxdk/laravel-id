<?php

declare(strict_types=1);

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

/**
 * GENERATES tests/Fixtures/audit/golden-vectors.json FROM THE PRE-EXTRACTION IMPLEMENTATION.
 *
 * Run once, deliberately, before the audit chain moved into cboxdk/laravel-audit-chain:
 *
 *     CBOX_ID_GENERATE_AUDIT_GOLDEN_VECTORS=1 vendor/bin/pest --filter=GenerateAuditGoldenVectors
 *
 * The fixture is EVIDENCE, not a snapshot to refresh: it records what the laravel-id
 * v1.19.x `DatabaseAuditLog` wrote, byte for byte, so that every later implementation
 * can be held to it (AuditGoldenVectorTest). Regenerating it from a later implementation
 * would prove only that the implementation agrees with itself — which is why this
 * generator is removed in the same change that swaps the implementation out.
 *
 * It drives the CURRENT public API only (record / checkpoint / Checkpointer), plus one
 * reflective read of the private canonicalPayload() so the fixture pins the exact bytes
 * that go into each hash, not only the hash.
 */
it('generates the audit golden vectors from the current implementation', function (): void {
    // A fixed master key, so the signing-key rows exported below can be re-opened by
    // the replay test and a re-signed checkpoint uses the very same key.
    $masterKey = base64_encode(str_repeat("\x42", 32));
    config(['cbox-id.crypto.key' => $masterKey]);
    app()->forgetInstance(SecretBox::class);
    app()->forgetInstance(KeyManager::class);
    app()->forgetInstance(TokenSigner::class);
    app()->forgetInstance(AuditLog::class);
    app()->forgetInstance(Checkpointer::class);

    $envA = '01J8ZK3V9Q4XW5T6Y7R8S9A0BC';
    $envB = '01J8ZK3V9Q4XW5T6Y7R8S9A0BD';
    $orgA = '01J8ZM0RGA0000000000000001';
    $orgB = '01J8ZM0RGB0000000000000002';
    $orgPlat = '01J8ZM0RGP0000000000000003';

    $base = Carbon::parse('2026-09-01 10:00:00', 'UTC');
    $minute = 0;

    /** @var list<array<string, mixed>> $operations */
    $operations = [];

    $canonical = new ReflectionMethod(DatabaseAuditLog::class, 'canonicalPayload');

    $record = function (?string $environment, AuditEvent $event) use (&$operations, &$minute, $base, $canonical): void {
        $at = $base->copy()->addMinutes($minute++)->addSeconds(7);
        $this->travelTo($at);

        $context = app(EnvironmentContext::class);
        $context->set($environment === null ? null : GenericEnvironment::of($environment));

        $entry = app(AuditLog::class)->record($event);

        // The bound AuditLog is the streaming decorator; the canonical form lives on
        // the database implementation underneath it, which holds no chain state.
        $inner = app()->make(DatabaseAuditLog::class);

        $operations[] = [
            'op' => 'record',
            'environment' => $environment,
            'at' => $at->toIso8601String(),
            'event' => [
                'action' => $event->action,
                'actor_type' => $event->actorType->value,
                'actor_id' => $event->actorId,
                'organization_id' => $event->organizationId,
                'target_type' => $event->targetType,
                'target_id' => $event->targetId,
                // Serialised with the exact PHP array shape preserved: list vs map,
                // integer keys and key ORDER all matter to canonicalize().
                'context_php' => serialize($event->context),
                'ip' => $event->ip,
            ],
            'expect' => [
                'environment_id' => $entry->environment_id,
                'scope' => $entry->scope,
                'sequence' => $entry->sequence,
                'prev_hash' => $entry->prev_hash,
                'hash' => $entry->hash,
                'canonical' => $canonical->invoke($inner, $entry),
            ],
        ];
    };

    $checkpoint = function (?string $environment, ?string $organizationId) use (&$operations, &$minute, $base): void {
        $at = $base->copy()->addMinutes($minute++)->addSeconds(30);
        $this->travelTo($at);

        app(EnvironmentContext::class)->set($environment === null ? null : GenericEnvironment::of($environment));

        try {
            $row = app(AuditLog::class)->checkpoint($organizationId);
        } catch (Throwable $failure) {
            // Recorded, not hidden: what the implementation DID is the evidence, and a
            // refusal is behaviour the replacement must reproduce too.
            $operations[] = [
                'op' => 'checkpoint',
                'environment' => $environment,
                'organization_id' => $organizationId,
                'at' => $at->toIso8601String(),
                'expect' => ['throws' => $failure::class],
            ];

            return;
        }

        [, $payload] = explode('.', $row->signature);

        $operations[] = [
            'op' => 'checkpoint',
            'environment' => $environment,
            'organization_id' => $organizationId,
            'at' => $at->toIso8601String(),
            'expect' => [
                'environment_id' => $row->environment_id,
                'scope' => $row->scope,
                'organization_id' => $row->organization_id,
                'up_to_sequence' => $row->up_to_sequence,
                'root_hash' => $row->root_hash,
                // The claim NAMES in signing order; values are compared separately
                // (`jti` is random per signature by design).
                'claim_order' => array_keys((array) json_decode(base64_decode(strtr($payload, '-_', '+/')), true)),
            ],
        ];
    };

    // ── The platform plane (no environment): the `__platform__` sentinel partition ──
    $record(null, new AuditEvent(action: 'operator.login', actorType: ActorType::Operator, actorId: 'op_1', ip: '198.51.100.7'));
    $record(null, new AuditEvent(
        action: 'operator.suspended_account',
        actorType: ActorType::Operator,
        actorId: 'op_1',
        targetType: 'organization',
        targetId: $orgPlat,
        context: ['reason' => 'fraud review', 'ticket' => 'OPS-4411'],
        ip: '2001:db8::1',
    ));
    $record(null, new AuditEvent(action: 'org.created', actorType: ActorType::OrganizationMember, actorId: 'mem_9', organizationId: $orgPlat, context: []));
    $checkpoint(null, null);
    $record(null, new AuditEvent(action: 'org.renamed', actorType: ActorType::OrganizationMember, actorId: 'mem_9', organizationId: $orgPlat, context: ['from' => 'Acme', 'to' => 'Acme ApS']));
    $record(null, AuditEvent::forSystem('platform.maintenance', ['window' => ['start' => '02:00', 'end' => '02:30']]));

    // ── Environment A: system scope + two organization scopes ──
    $record($envA, AuditEvent::forSystem('environment.created'));
    $record($envA, new AuditEvent(
        action: 'user.login',
        actorType: ActorType::User,
        actorId: 'usr_01',
        organizationId: $orgA,
        targetType: 'session',
        targetId: 'ses_01',
        // Nested, UNSORTED keys at every level, lists that must NOT be re-ordered,
        // and a sparse integer-keyed array (encodes as an object after ksort).
        context: [
            'zeta' => 1,
            'alpha' => ['nested_z' => true, 'nested_a' => [3, 1, 2], 'm' => ['y' => null, 'x' => false]],
            'list' => ['b', 'a', 'c'],
            'sparse' => [2 => 'two', 0 => 'zero'],
            'method' => 'password',
        ],
        ip: '203.0.113.9',
    ));
    $record($envA, new AuditEvent(
        action: 'user.profile_updated',
        actorType: ActorType::User,
        actorId: 'usr_01',
        organizationId: $orgA,
        targetType: 'user',
        targetId: 'usr_01',
        // Unicode that must stay UNESCAPED, and characters JSON escapes regardless.
        context: [
            'name' => 'Søren Ærø Åberg',
            'city' => '東京',
            'emoji' => '🔐👩‍💻',
            'quote' => 'she said "hi"',
            'newline' => "line1\nline2\ttab",
            'nul' => "a\u{0000}b",
            'rtl' => 'مرحبا',
        ],
    ));
    $record($envA, new AuditEvent(
        action: 'app.redirect_uri_added',
        actorType: ActorType::Service,
        actorId: 'client_7',
        organizationId: $orgA,
        targetType: 'oauth_client',
        targetId: 'client_7',
        // Slashes stay unescaped; backslashes and `</script>` are the edge.
        context: [
            'uri' => 'https://app.example.test/callback/a/b?x=1&y=2',
            'windows' => 'C:\\Program Files\\Cbox',
            'html' => '</script><b>',
            'unicode_escape_literal' => '\\u00e6',
        ],
    ));
    $record($envA, new AuditEvent(
        action: 'invitation.created',
        actorType: ActorType::OrganizationMember,
        actorId: null,
        organizationId: $orgB,
        targetType: null,
        targetId: 'a.very.long.email.address+with.tag@subdomain.example.test',
        // Scalars of every JSON type, including numbers PHP could render two ways,
        // numeric-string keys (PHP turns "10" into int 10) mixed with string keys.
        context: [
            'count' => 42,
            'negative' => -7,
            'big' => PHP_INT_MAX,
            'ratio' => 0.1,
            'whole_float' => 1.0,
            'tiny' => 1.5e-7,
            'yes' => true,
            'no' => false,
            'nothing' => null,
            'empty_list' => [],
            '10' => 'ten',
            '9' => 'nine',
            'b' => 'bee',
            'a' => 'ay',
        ],
        ip: null,
    ));
    $record($envA, new AuditEvent(action: 'role.assigned', actorType: ActorType::System, organizationId: $orgA, targetType: 'user', targetId: 'usr_02', context: ['role_id' => 'admin']));
    $checkpoint($envA, $orgA);
    $record($envA, new AuditEvent(action: 'role.revoked', actorType: ActorType::Operator, actorId: 'op_2', organizationId: $orgA, targetType: 'user', targetId: 'usr_02', context: ['role_id' => 'admin', 'by' => ['kind' => 'operator']]));
    $record($envA, AuditEvent::forSystem('environment.keys_rotated', ['alg' => 'RS256']));

    // ── Environment B: the SAME organization id as a scope in a different partition ──
    $record($envB, new AuditEvent(action: 'user.login', actorType: ActorType::User, actorId: 'usr_01', organizationId: $orgA, context: ['method' => 'passkey']));
    $record($envB, new AuditEvent(action: 'user.logout', actorType: ActorType::User, actorId: 'usr_01', organizationId: $orgA));
    $checkpoint($envB, $orgA);

    // ── The Checkpointer pass, which re-enters each chain's environment itself ──
    $at = $base->copy()->addMinutes($minute++);
    $this->travelTo($at);
    app(EnvironmentContext::class)->set(GenericEnvironment::of('env_test'));
    $outcomes = app(Checkpointer::class)->checkpointAll();

    $operations[] = [
        'op' => 'checkpoint_all',
        'at' => $at->toIso8601String(),
        'expect' => array_map(static fn ($outcome): array => [
            'environment_id' => $outcome->environmentId,
            'scope' => $outcome->scope,
            'head_sequence' => $outcome->headSequence,
            'checkpointed_sequence' => $outcome->checkpointedSequence,
            'signed' => $outcome->wasSigned(),
            'skipped' => $outcome->skippedReason,
            'failed' => $outcome->failureReason,
        ], $outcomes),
    ];

    // ── What verification answered over the rows as written ──
    $verifications = [];

    $chains = DB::table('audit_logs')->select('environment_id', 'scope')->selectRaw('count(*) as n')
        ->groupBy('environment_id', 'scope')->orderBy('environment_id')->orderBy('scope')->get();

    foreach ($chains as $chain) {
        $environment = (string) $chain->environment_id;
        $scope = (string) $chain->scope;
        $organizationId = $scope === DatabaseAuditLog::SYSTEM_SCOPE ? null : $scope;

        foreach (['no_environment' => null, 'own_environment' => $environment] as $as => $contextKey) {
            if ($as === 'no_environment' && $environment !== DatabaseAuditLog::PLATFORM_ENVIRONMENT) {
                continue;
            }

            app(EnvironmentContext::class)->set($contextKey === null ? null : GenericEnvironment::of($contextKey));
            $result = app(AuditLog::class)->verifyChain($organizationId);

            $verifications[] = [
                'environment_id' => $environment,
                'scope' => $scope,
                'verified_as' => $as,
                'valid' => $result->valid,
                'verified_count' => $result->verifiedCount,
                'broken_at_sequence' => $result->brokenAtSequence,
                'reason' => $result->reason,
                'head_sequence' => app(AuditLog::class)->headSequence($organizationId),
            ];
        }
    }

    app(EnvironmentContext::class)->set(GenericEnvironment::of('env_test'));

    $rows = static fn (string $table): array => DB::table($table)->orderBy('id')->get()
        ->map(static fn (object $row): array => (array) $row)->all();

    $fixture = [
        '_provenance' => [
            'generated_by' => 'tests/Feature/Kernel/Audit/GoldenVectors/GenerateAuditGoldenVectorsTest.php',
            'implementation' => 'cboxdk/laravel-id Cbox\\Id\\Kernel\\Audit\\DatabaseAuditLog, pre-extraction (v1.19.3, 9ab6613)',
            'php' => PHP_VERSION,
            'database' => DB::connection()->getDriverName(),
            'note' => 'Evidence of what the pre-extraction implementation wrote. Never regenerate from a later implementation.',
        ],
        'crypto_master_key' => $masterKey,
        'operations' => $operations,
        'verifications' => $verifications,
        'tables' => [
            'audit_logs' => $rows('audit_logs'),
            'audit_checkpoints' => $rows('audit_checkpoints'),
            'signing_keys' => $rows('signing_keys'),
        ],
    ];

    $path = dirname(__DIR__, 4).'/Fixtures/audit/golden-vectors.json';

    if (! is_dir(dirname($path))) {
        mkdir(dirname($path), 0755, true);
    }

    file_put_contents($path, json_encode($fixture, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n");

    expect(AuditEntry::query()->withoutGlobalScopes()->count())->toBe(count(array_filter($operations, static fn (array $op): bool => $op['op'] === 'record')));
})->skip(
    fn (): bool => getenv('CBOX_ID_GENERATE_AUDIT_GOLDEN_VECTORS') !== '1',
    'writes the golden-vector fixture; run deliberately with CBOX_ID_GENERATE_AUDIT_GOLDEN_VECTORS=1',
);
