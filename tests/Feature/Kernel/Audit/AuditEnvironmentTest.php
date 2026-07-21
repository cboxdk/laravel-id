<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\DatabaseAuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * The audit trail is the most sensitive read surface on the platform: it records who did
 * what to whom across every tenant. It was the ONE table with no environment column and
 * no tenancy scope, so any authenticated environment admin could page through every
 * customer's security trail — and, because account-plane activity is written into the
 * same table, every other account's activity too.
 *
 * The hash chain is per (environment, scope). That matters beyond isolation: the
 * '__system__' scope used to be a single global chain, so operator and environment-level
 * entries from unrelated customers interleaved in it and every writer contended on one
 * chain head.
 */
function auditEntry(string $action, ?string $organizationId = null): AuditEntry
{
    return app(AuditLog::class)->record(new AuditEvent(
        action: $action,
        actorType: ActorType::System,
        organizationId: $organizationId,
    ));
}

it('never shows one environment the audit trail of another', function (): void {
    $this->runAsEnvironment('env_a', fn () => auditEntry('user.created', 'org_a'));
    $this->runAsEnvironment('env_b', fn () => auditEntry('user.deleted', 'org_b'));

    $this->runAsEnvironment('env_a', function (): void {
        $actions = AuditEntry::query()->pluck('action')->all();

        expect($actions)->toContain('user.created')
            ->and($actions)->not->toContain('user.deleted');
    });
});

it('isolates the system-scope chain per environment', function (): void {
    // Both write to the '__system__' scope (no organization) — previously ONE chain.
    $a = $this->runAsEnvironment('env_a', fn () => auditEntry('operator.login'));
    $b = $this->runAsEnvironment('env_b', fn () => auditEntry('operator.login'));

    // Each environment starts its own chain at sequence 1 rather than sharing one.
    expect($a->sequence)->toBe(1)
        ->and($b->sequence)->toBe(1)
        ->and($a->environment_id)->toBe('env_a')
        ->and($b->environment_id)->toBe('env_b');
});

it('keeps the chain verifiable within an environment', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        auditEntry('one', 'org_a');
        auditEntry('two', 'org_a');
        auditEntry('three', 'org_a');

        $verification = app(AuditLog::class)->verifyChain('org_a');

        expect($verification->valid)->toBeTrue()
            ->and($verification->verifiedCount)->toBe(3)
            ->and($verification->brokenAtSequence)->toBeNull();
    });
});

it('stamps the environment on every entry', function (): void {
    $entry = $this->runAsEnvironment('env_a', fn () => auditEntry('user.created', 'org_a'));

    expect($entry->environment_id)->toBe('env_a');
});

/**
 * The account-management plane deliberately runs with NO environment. Every test in this
 * suite pins one (tests/TestCase.php), which is exactly why this path was never
 * exercised — and why the chain silently stopped being a chain there.
 */
it('keeps a real chain when no environment is in context', function (): void {
    app(EnvironmentContext::class)->set(null);

    $a = auditEntry('operator.login');
    $b = auditEntry('operator.suspended_account');
    $c = auditEntry('operator.logout');

    // Sequences must ADVANCE. Before the fix every one of these was sequence 1 with the
    // genesis hash, because the chain head was read through a global scope that matches
    // nothing when no environment is set.
    expect([$a->sequence, $b->sequence, $c->sequence])->toBe([1, 2, 3])
        ->and($b->prev_hash)->toBe($a->hash)
        ->and($c->prev_hash)->toBe($b->hash);

    // …and the platform chain actually verifies, rather than reporting valid(0) because
    // it matched no rows at all.
    $verification = app(AuditLog::class)->verifyChain();

    expect($verification->valid)->toBeTrue()
        ->and($verification->verifiedCount)->toBe(3);
});

it('stamps the platform sentinel rather than leaving the environment null', function (): void {
    app(EnvironmentContext::class)->set(null);

    // A NULL here is what made the (environment_id, scope, sequence) unique key inert:
    // SQL treats NULLs as distinct, so the constraint never fired.
    expect(auditEntry('operator.login')->environment_id)
        ->toBe(DatabaseAuditLog::PLATFORM_ENVIRONMENT);
});

/**
 * The chain is DEFINED as per-(environment, scope), so the environment must be inside the
 * hash — otherwise a row can be moved between environments with a plain UPDATE and the
 * chain still reports itself intact.
 */
it('detects an entry moved between environments', function (): void {
    $entry = $this->runAsEnvironment('env_a', fn () => auditEntry('user.created', 'org_a'));

    DB::table('audit_logs')->where('id', $entry->id)->update(['environment_id' => 'env_b']);

    $this->runAsEnvironment('env_b', function (): void {
        $verification = app(AuditLog::class)->verifyChain('org_a');

        expect($verification->valid)->toBeFalse();
    });
});
