<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\AuditServiceProvider;
use Cbox\Id\Kernel\Audit\Checkpointer;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Models\AuditCheckpoint;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Audit\ValueObjects\ChainVerification;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * Until this command existed, `AuditLog::checkpoint()` had no caller but a test:
 * `audit_checkpoints` was empty everywhere, `verifyCheckpointAnchor()` returned null
 * on every call, and the trail had NO tail-deletion detection at all. These cover
 * that it now can be driven — and, just as deliberately, that it is not driven by
 * default. See Checkpointer for why the first signature is a one-way door.
 */
it('signs a checkpoint over every chain that has entries', function (): void {
    $log = app(AuditLog::class);

    $log->record(AuditEvent::forSystem('a'));
    $log->record(AuditEvent::forSystem('b'));
    $log->record(new AuditEvent(action: 'org.event', organizationId: 'org_alpha'));

    $outcomes = app(Checkpointer::class)->checkpointAll();

    expect($outcomes)->toHaveCount(2);

    $signed = AuditCheckpoint::query()
        ->withoutGlobalScope(EnvironmentScope::class)
        ->get()
        ->keyBy('scope');

    expect($signed)->toHaveCount(2)
        ->and($signed['__system__']->up_to_sequence)->toBe(2)
        ->and($signed['org_alpha']->up_to_sequence)->toBe(1)
        ->and($signed['org_alpha']->organization_id)->toBe('org_alpha');

    // The point of the exercise: the anchored entry is now attested, so removing it
    // is detectable — which is what nothing in the platform could see before.
    AuditEntry::query()->where('scope', '__system__')->where('sequence', 2)->delete();

    expect($log->verifyChain(null)->valid)->toBeFalse();
});

it('is idempotent — a second pass over an unchanged chain signs nothing', function (): void {
    app(AuditLog::class)->record(AuditEvent::forSystem('a'));

    app(Checkpointer::class)->checkpointAll();
    $second = app(Checkpointer::class)->checkpointAll();

    expect($second)->toHaveCount(1)
        ->and($second[0]->wasSkipped())->toBeTrue()
        ->and($second[0]->skippedReason)->toBe('already checkpointed at head')
        ->and(DB::table('audit_checkpoints')->count())->toBe(1);

    // ...but a chain that HAS advanced is signed again, at its new head.
    app(AuditLog::class)->record(AuditEvent::forSystem('b'));

    $third = app(Checkpointer::class)->checkpointAll();

    expect($third[0]->wasSigned())->toBeTrue()
        ->and($third[0]->headSequence)->toBe(2)
        ->and($third[0]->checkpointedSequence)->toBe(1)
        ->and(DB::table('audit_checkpoints')->count())->toBe(2);
});

it('checkpoints each environment against its own chain', function (): void {
    $this->runAsEnvironment('env_one', fn () => app(AuditLog::class)->record(AuditEvent::forSystem('one')));
    $this->runAsEnvironment('env_two', function (): void {
        app(AuditLog::class)->record(AuditEvent::forSystem('two.a'));
        app(AuditLog::class)->record(AuditEvent::forSystem('two.b'));
    });

    // The pass runs from whatever environment the scheduler happened to be in — it
    // must still see, and correctly attribute, every environment's chain.
    $outcomes = app(Checkpointer::class)->checkpointAll();

    $byEnvironment = [];

    foreach ($outcomes as $outcome) {
        $byEnvironment[$outcome->environmentId] = $outcome->headSequence;
    }

    expect($byEnvironment)->toBe(['env_one' => 1, 'env_two' => 2]);

    $rows = DB::table('audit_checkpoints')->orderBy('environment_id')->get();

    expect($rows->pluck('environment_id')->all())->toBe(['env_one', 'env_two'])
        ->and($rows->pluck('up_to_sequence')->map(intval(...))->all())->toBe([1, 2]);
});

it('counts without signing on a dry run', function (): void {
    app(AuditLog::class)->record(AuditEvent::forSystem('a'));

    $outcomes = app(Checkpointer::class)->checkpointAll(dryRun: true);

    expect($outcomes[0]->wasSkipped())->toBeFalse()
        ->and($outcomes[0]->wasSigned())->toBeFalse()
        ->and($outcomes[0]->headSequence)->toBe(1)
        ->and(DB::table('audit_checkpoints')->count())->toBe(0);
});

it('narrows to the named environments and scopes', function (): void {
    app(AuditLog::class)->record(AuditEvent::forSystem('system'));
    app(AuditLog::class)->record(new AuditEvent(action: 'org.event', organizationId: 'org_alpha'));

    $outcomes = app(Checkpointer::class)->checkpointAll(scopes: ['org_alpha']);

    expect($outcomes)->toHaveCount(1)
        ->and($outcomes[0]->scope)->toBe('org_alpha')
        ->and(DB::table('audit_checkpoints')->pluck('scope')->all())->toBe(['org_alpha']);

    expect(app(Checkpointer::class)->checkpointAll(environmentIds: ['env_absent']))->toBe([]);
});

it('signs from the command and says what it did', function (): void {
    app(AuditLog::class)->record(AuditEvent::forSystem('a'));

    $this->artisan('cbox-id:audit:checkpoint')
        ->expectsOutputToContain('Signed 1 checkpoint(s) over 1 chain(s).')
        ->expectsOutputToContain('A signed checkpoint is permanent evidence.')
        ->assertSuccessful();

    expect(DB::table('audit_checkpoints')->count())->toBe(1);

    $this->artisan('cbox-id:audit:checkpoint --dry-run')
        ->expectsOutputToContain('Dry run — nothing will be signed.')
        ->assertSuccessful();

    // --force overrides the idempotence skip, for an operator who wants a fresh
    // signature (a rotated key, an external anchoring run) over an unchanged head.
    $this->artisan('cbox-id:audit:checkpoint --force')->assertSuccessful();

    expect(DB::table('audit_checkpoints')->count())->toBe(2);
});

it('reports a chain it could not sign, keeps going, and exits non-zero', function (): void {
    app(AuditLog::class)->record(AuditEvent::forSystem('system'));
    app(AuditLog::class)->record(new AuditEvent(action: 'org.event', organizationId: 'org_alpha'));

    // One unsignable chain (a missing key for its environment, a signer outage) must
    // not stop the pass before every chain after it.
    $log = app(AuditLog::class);

    app()->instance(Checkpointer::class, new Checkpointer(new class($log) implements AuditLog
    {
        public function __construct(private readonly AuditLog $inner) {}

        public function record(AuditEvent $event): AuditEntry
        {
            return $this->inner->record($event);
        }

        public function verifyChain(?string $organizationId = null, int $fromSequence = 1, ?int $toSequence = null): ChainVerification
        {
            return $this->inner->verifyChain($organizationId, $fromSequence, $toSequence);
        }

        public function headSequence(?string $organizationId = null): int
        {
            return $this->inner->headSequence($organizationId);
        }

        public function checkpoint(?string $organizationId = null): AuditCheckpoint
        {
            if ($organizationId === 'org_alpha') {
                throw new RuntimeException('no signing key');
            }

            return $this->inner->checkpoint($organizationId);
        }
    }));

    $this->artisan('cbox-id:audit:checkpoint')
        ->expectsOutputToContain('1 chain(s) could not be checkpointed.')
        ->assertFailed();

    // The healthy chain was still signed.
    expect(DB::table('audit_checkpoints')->pluck('scope')->all())->toBe(['__system__']);
});

it('reports honestly when there is nothing to checkpoint', function (): void {
    $this->artisan('cbox-id:audit:checkpoint')
        ->expectsOutputToContain('No audit chains to checkpoint.')
        ->assertSuccessful();
});

/**
 * The one-way door. Signing the first checkpoint forecloses the single re-chain the
 * GDPR-erasure design needs (hash the ciphertext, not the plaintext), so the schedule
 * ships OFF and an operator turns it on deliberately, in the documented order.
 */
it('is not scheduled by default, and is scheduled when the operator opts in', function (): void {
    $scheduled = static fn (): array => array_values(array_filter(
        app(Schedule::class)->events(),
        static fn (object $event): bool => $event->description === 'cbox-id:audit:checkpoint',
    ));

    expect(config('cbox-id.audit.checkpoint.schedule'))->toBeFalse()
        ->and($scheduled())->toBe([]);

    // Re-boot the provider with the flag on: the same registration, opted into.
    config(['cbox-id.audit.checkpoint.schedule' => true]);

    app()->register(AuditServiceProvider::class, force: true);

    expect($scheduled())->toHaveCount(1)
        ->and($scheduled()[0]->expression)->toBe('40 2 * * *');
});
