<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('flags a proposed grant that would complete a toxic combination', function (): void {
    $sod = app(SegregationOfDuties::class);
    $createPo = app(Roles::class)->define('acme', 'create-po');
    $approvePay = app(Roles::class)->define('acme', 'approve-payment');
    $sod->definePolicy('acme', 'PO vs payment', [$createPo->id, $approvePay->id]);

    app(Roles::class)->assign('acme', 'user-1', $createPo->id);

    // Granting the conflicting role now would violate.
    expect($sod->wouldViolate('acme', 'user-1', $approvePay->id))->toBeTrue();

    $decision = $sod->evaluate('acme', 'user-1', $approvePay->id);
    expect($decision->allowed)->toBeFalse()
        ->and($decision->reason)->toStartWith('sod:');

    // A user holding neither conflicting role is fine.
    expect($sod->wouldViolate('acme', 'user-2', $approvePay->id))->toBeFalse();
});

it('allows a proposed grant with no conflict', function (): void {
    $sod = app(SegregationOfDuties::class);
    $a = app(Roles::class)->define('acme', 'role-a');
    $b = app(Roles::class)->define('acme', 'role-b');
    $sod->definePolicy('acme', 'a vs b', [$a->id, $b->id]);

    // The subject holds neither; proposing one is allowed.
    expect($sod->evaluate('acme', 'user-1', $a->id)->allowed)->toBeTrue();
});

it('detects existing violations via violationsFor and scan', function (): void {
    $sod = app(SegregationOfDuties::class);
    $a = app(Roles::class)->define('acme', 'role-a');
    $b = app(Roles::class)->define('acme', 'role-b');
    $sod->definePolicy('acme', 'a vs b', [$a->id, $b->id]);

    app(Roles::class)->assign('acme', 'user-1', $a->id);
    app(Roles::class)->assign('acme', 'user-1', $b->id);

    $forUser = $sod->violationsFor('acme', 'user-1');
    expect($forUser)->toHaveCount(1)
        ->and($forUser[0]->conflictingRoleIds)->toEqualCanonicalizing([$a->id, $b->id]);

    expect($sod->scan('acme'))->toHaveCount(1);
});

it('ignores inactive policies', function (): void {
    $sod = app(SegregationOfDuties::class);
    $a = app(Roles::class)->define('acme', 'role-a');
    $b = app(Roles::class)->define('acme', 'role-b');
    $policy = $sod->definePolicy('acme', 'a vs b', [$a->id, $b->id]);
    $sod->setActive($policy->id, false);

    app(Roles::class)->assign('acme', 'user-1', $a->id);

    expect($sod->wouldViolate('acme', 'user-1', $b->id))->toBeFalse()
        ->and($sod->violationsFor('acme', 'user-1'))->toBe([]);
});

it('applies an environment-wide (null-org) policy in any org', function (): void {
    $sod = app(SegregationOfDuties::class);
    $a = app(Roles::class)->define('acme', 'role-a');
    $b = app(Roles::class)->define('acme', 'role-b');
    $sod->definePolicy(null, 'global a vs b', [$a->id, $b->id]);

    app(Roles::class)->assign('acme', 'user-1', $a->id);

    expect($sod->wouldViolate('acme', 'user-1', $b->id))->toBeTrue();
});
