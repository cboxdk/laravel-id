<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Illuminate\Foundation\Testing\RefreshDatabase;

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
