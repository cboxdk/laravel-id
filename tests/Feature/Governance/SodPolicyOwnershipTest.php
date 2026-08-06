<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Cbox\Id\Governance\Exceptions\UnknownSodPolicy;
use Cbox\Id\Governance\Models\SodPolicy;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * An environment-wide policy (organization_id null) is the CONTROL PLANE's own
 * toxic-combination rule and binds every tenant in the environment. An org admin who
 * could deactivate it could then grant themselves the very pair it forbids, so the
 * org-scoped toggle refuses anything the org does not own.
 */
function sodPair(string $orgId): array
{
    return [
        app(Roles::class)->define($orgId, 'create-po')->id,
        app(Roles::class)->define($orgId, 'approve-payment')->id,
    ];
}

it('refuses to let an organization deactivate an environment-wide policy', function (): void {
    $sod = app(SegregationOfDuties::class);
    $policy = $sod->definePolicy(null, 'Env-wide PO vs payment', sodPair('acme'));

    expect(fn () => $sod->setActiveForOrganization('acme', $policy->id, false))
        ->toThrow(UnknownSodPolicy::class);

    // Still active — and still enforced for the org that tried to switch it off.
    expect(SodPolicy::query()->whereKey($policy->id)->value('active'))->toBeTrue();
});

it('refuses to let one organization deactivate another organization\'s policy', function (): void {
    $sod = app(SegregationOfDuties::class);
    $policy = $sod->definePolicy('acme', 'Acme PO vs payment', sodPair('acme'));

    expect(fn () => $sod->setActiveForOrganization('globex', $policy->id, false))
        ->toThrow(UnknownSodPolicy::class);

    expect(SodPolicy::query()->whereKey($policy->id)->value('active'))->toBeTrue();
});

it('lets an organization toggle its OWN policy, and records it', function (): void {
    $sod = app(SegregationOfDuties::class);
    $policy = $sod->definePolicy('acme', 'Acme PO vs payment', sodPair('acme'));

    $sod->setActiveForOrganization('acme', $policy->id, false);

    expect(SodPolicy::query()->whereKey($policy->id)->value('active'))->toBeFalse()
        ->and(AuditEntry::query()->where('action', 'sod.policy_deactivated')->count())->toBe(1);

    $sod->setActiveForOrganization('acme', $policy->id, true);

    expect(SodPolicy::query()->whereKey($policy->id)->value('active'))->toBeTrue()
        ->and(AuditEntry::query()->where('action', 'sod.policy_activated')->count())->toBe(1);
});

it('still lets the environment plane toggle an environment-wide policy', function (): void {
    $sod = app(SegregationOfDuties::class);
    $policy = $sod->definePolicy(null, 'Env-wide PO vs payment', sodPair('acme'));

    $sod->setActive($policy->id, false);

    expect(SodPolicy::query()->whereKey($policy->id)->value('active'))->toBeFalse()
        ->and(AuditEntry::query()->where('action', 'sod.policy_deactivated')->count())->toBe(1);
});
