<?php

declare(strict_types=1);

use Cbox\AuditChain\Contracts\AuditChain;
use Cbox\AuditChain\Contracts\CheckpointAnchor;
use Cbox\AuditChain\Enums\ChainBreak;
use Cbox\AuditChain\Exceptions\AuditChainException;
use Cbox\AuditChain\Exceptions\CannotAppendToChain;
use Cbox\AuditChain\Exceptions\CannotCheckpointEmptyChain;
use Cbox\AuditChain\ValueObjects\ChainActor;
use Cbox\AuditChain\ValueObjects\ChainEvent;
use Cbox\AuditChain\ValueObjects\ChainKey;
use Cbox\Id\Kernel\Audit\Chain\AuditLogChain;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\DatabaseAuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotAppendToAuditChain;
use Cbox\Id\Kernel\Audit\Exceptions\CannotCheckpointEmptyScope;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

uses(RefreshDatabase::class);

/*
 * The audit chain now runs on cboxdk/laravel-audit-chain. These cover what that adds to
 * the platform — and that none of it can change the platform's own trail.
 * (That the trail itself is byte-for-byte unchanged is GoldenVectors/.)
 */

it('answers the package contract with the platform trail, per environment', function (): void {
    $chain = app(AuditChain::class);

    expect($chain)->toBeInstanceOf(AuditLogChain::class);

    // Recorded from env_test's context into env_other's chain: the key decides.
    $entry = $chain->record(
        ChainKey::of('env_other', 'org_a'),
        ChainEvent::by(ChainActor::of('user', 'usr_1'), 'user.login', ['method' => 'passkey']),
    );

    expect($entry)->toBeInstanceOf(AuditEntry::class)
        ->and($entry->environment_id)->toBe('env_other')
        ->and($entry->scope)->toBe('org_a')
        ->and($entry->organization_id)->toBe('org_a')
        ->and($chain->head(ChainKey::of('env_other', 'org_a')))->toBe(1)
        ->and($chain->verify(ChainKey::of('env_other', 'org_a'))->valid)->toBeTrue();

    // ...and it is the same chain the AuditLog contract sees from inside that environment.
    $this->runAsEnvironment('env_other', function (): void {
        expect(app(AuditLog::class)->headSequence('org_a'))->toBe(1);
    });
});

it('goes through the AuditLog stack, so a faked or decorated log sees it', function (): void {
    $audit = $this->fakeAudit();

    app(AuditChain::class)->record(ChainKey::of('env_test', DatabaseAuditLog::SYSTEM_SCOPE), ChainEvent::system('platform.probe'));

    $audit->assertRecorded('platform.probe', fn (AuditEvent $event): bool => $event->organizationId === null);
});

it('verifies every environment\'s chains from the package command, platform plane included', function (): void {
    $this->runAsEnvironment('env_a', fn () => app(AuditLog::class)->record(new AuditEvent(action: 'a', organizationId: 'org_a')));
    $this->runAsEnvironment('env_b', fn () => app(AuditLog::class)->record(AuditEvent::forSystem('b')));

    $this->forgetEnvironment();
    app(AuditLog::class)->record(AuditEvent::forSystem('operator.login'));
    $this->actingAsEnvironment('env_test');

    $this->artisan('audit-chain:verify')
        ->expectsOutputToContain('All 3 chain(s) verified.')
        ->assertSuccessful();

    DB::table('audit_logs')->where('environment_id', 'env_b')->update(['action' => 'forged']);

    $this->artisan('audit-chain:verify')
        ->expectsOutputToContain('1 of 3 chain(s) failed verification.')
        ->assertFailed();

    expect(app(AuditChain::class)->verify(ChainKey::of('env_b', DatabaseAuditLog::SYSTEM_SCOPE))->break)
        ->toBe(ChainBreak::ContentMismatch);
});

it('signs platform checkpoints from the package command exactly as the platform command does', function (): void {
    $this->runAsEnvironment('env_a', fn () => app(AuditLog::class)->record(new AuditEvent(action: 'a', organizationId: 'org_a')));

    $this->artisan('audit-chain:checkpoint')
        ->expectsOutputToContain('Signed 1 checkpoint(s) over 1 chain(s).')
        ->assertSuccessful();

    $row = DB::table('audit_checkpoints')->first();

    expect($row)->not->toBeNull()
        ->and($row?->environment_id)->toBe('env_a')
        ->and($row?->organization_id)->toBe('org_a');

    // A Crypto-kernel JWT with the platform's checkpoint type, from env_a's own keys.
    $claims = $this->runAsEnvironment('env_a', fn () => app(TokenSigner::class)->verify((string) $row?->signature, [SigningAlg::RS256]));

    expect($claims->string('typ'))->toBe('cbox-id.audit.checkpoint');

    // ...and the platform's own pass sees it as done.
    $this->artisan('cbox-id:audit:checkpoint')
        ->expectsOutputToContain('Signed 0 checkpoint(s) over 1 chain(s).')
        ->assertSuccessful();
});

it('keeps the platform trail independent of the package config', function (): void {
    // Everything a host might set for ITS OWN use of the package.
    config([
        'audit-chain.models.entry' => 'App\\Models\\SomethingElse',
        'audit-chain.storage.tables.entries' => 'other_table',
        'audit-chain.storage.partition_column' => 'tenant_id',
        'audit-chain.codec.extra_columns' => ['whatever'],
        'audit-chain.signing.key_id' => null,
        'audit-chain.signing.secret_key' => null,
    ]);

    $log = app(AuditLog::class);

    $log->record(new AuditEvent(action: 'a', organizationId: 'org_a'));
    $checkpoint = $log->checkpoint('org_a');

    expect(DB::table('audit_logs')->count())->toBe(1)
        ->and($checkpoint->signature)->toStartWith('ey') // a JWT, not an acp1 token
        ->and($log->verifyChain('org_a')->valid)->toBeTrue();
});

it('exports platform checkpoints through the package anchor when one is configured', function (): void {
    Storage::fake('anchors');
    config(['audit-chain.anchor.driver' => 'filesystem', 'audit-chain.anchor.disk' => 'anchors']);

    foreach ([CheckpointAnchor::class, AuditLog::class] as $abstract) {
        app()->forgetInstance($abstract);
    }

    app(AuditLog::class)->record(new AuditEvent(action: 'a', organizationId: 'org_a'));
    $checkpoint = app(AuditLog::class)->checkpoint('org_a');

    $files = Storage::disk('anchors')->allFiles();

    expect($files)->toHaveCount(1)
        ->and($files[0])->toStartWith('audit-chain/checkpoints/env_test/org_a/00000000000000000001-');

    $document = json_decode((string) Storage::disk('anchors')->get($files[0]), true, flags: JSON_THROW_ON_ERROR);

    expect($document['token'])->toBe($checkpoint->signature)
        ->and($document['root_hash'])->toBe($checkpoint->root_hash);
});

it('keeps the platform exceptions, now also catchable as the package\'s', function (): void {
    expect(fn () => app(AuditLog::class)->checkpoint('org_empty'))
        ->toThrow(CannotCheckpointEmptyScope::class, 'Cannot checkpoint scope [org_empty]: it has no audit entries yet.');

    $empty = CannotCheckpointEmptyScope::make('x');
    $append = CannotAppendToAuditChain::afterAttempts('x', 8, new RuntimeException('dup'));

    expect($empty)->toBeInstanceOf(CannotCheckpointEmptyChain::class)
        ->toBeInstanceOf(RuntimeException::class)
        ->toBeInstanceOf(AuditChainException::class)
        ->and($append)->toBeInstanceOf(CannotAppendToChain::class)
        ->toBeInstanceOf(RuntimeException::class)
        ->and($append->attempts)->toBe(8)
        ->and($append->getMessage())->toBe('Could not append to audit chain [x]: the next sequence was taken by a concurrent writer on all 8 attempts.');
});

it('still raises the platform exception, with the collision as its cause, when the budget runs out', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('first'));

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

    try {
        $log->record(AuditEvent::forSystem('second'));
        $this->fail('expected the append to give up');
    } catch (CannotAppendToAuditChain $exhausted) {
        expect($exhausted->getMessage())->toBe('Could not append to audit chain [__system__]: the next sequence was taken by a concurrent writer on all 8 attempts.')
            ->and($exhausted->getPrevious())->toBeInstanceOf(QueryException::class);
    }
});

it('registers the package commands, and schedules none of them by default', function (): void {
    $commands = array_keys(Artisan::all());

    expect($commands)->toContain('audit-chain:checkpoint', 'audit-chain:verify', 'audit-chain:keygen', 'cbox-id:audit:checkpoint');

    $scheduled = array_map(static fn ($event): ?string => $event->description, app(Schedule::class)->events());

    expect($scheduled)->not->toContain('audit-chain:checkpoint')
        ->and($scheduled)->not->toContain('audit-chain:verify')
        ->and($scheduled)->not->toContain('cbox-id:audit:checkpoint');
});
