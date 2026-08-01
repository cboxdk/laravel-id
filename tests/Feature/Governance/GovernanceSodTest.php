<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\GrantRefused;
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

/**
 * The detective control, and why it still has a job now that the preventive one runs at
 * the grant chokepoint.
 *
 * The policy is defined AFTER both roles are held — which is the only way a violation can
 * come into existence from here on, and the ordinary way it happens in practice: someone
 * writes down a rule about a combination people already have. The previous version of
 * this test granted the roles after defining the policy, which the guard now refuses, and
 * which never described a state a running deployment could reach anyway.
 */
it('detects existing violations via violationsFor and scan', function (): void {
    $sod = app(SegregationOfDuties::class);
    $a = app(Roles::class)->define('acme', 'role-a');
    $b = app(Roles::class)->define('acme', 'role-b');

    app(Roles::class)->assign('acme', 'user-1', $a->id);
    app(Roles::class)->assign('acme', 'user-1', $b->id);

    $sod->definePolicy('acme', 'a vs b', [$a->id, $b->id]);

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

/**
 * The path the gate never covered.
 *
 * Segregation of duties was enforced by the host, in front of the console's manual grant
 * paths. Directory group→role mappings are reconciled INSIDE the framework, so they were
 * the one grant path a host cannot get in front of — and a user added to two upstream
 * groups received the forbidden pair silently, on the next reconcile. The detective scan
 * would report it afterwards, which is not what a customer is buying when they ask you to
 * prove a person cannot hold both roles.
 *
 * The refusal is skipped and audited rather than fatal: one person's conflicting group
 * membership must not abandon the rest of the directory's sync.
 */
it('refuses a conflicting role arriving from a directory group mapping', function (): void {
    $sod = app(SegregationOfDuties::class);
    $roles = app(Roles::class);
    $approver = $roles->define('acme', 'approver');
    $payer = $roles->define('acme', 'payer');
    $sod->definePolicy('acme', 'approver vs payer', [$approver->id, $payer->id]);

    $roles->assign('acme', 'user-1', $approver->id);

    expect(fn () => $roles->assign('acme', 'user-1', $payer->id, GrantSource::Pushed))
        ->toThrow(GrantRefused::class, 'approver vs payer');

    // And the state is unchanged: the refusal happens before the row is written.
    expect($sod->violationsFor('acme', 'user-1'))->toBe([]);
});

/**
 * A grant with no conflict is untouched — the guard is a veto, not a gate everything has
 * to ask permission from. Worth pinning: a guard that refused too much would be found
 * immediately, and one that refuses too little is what this whole change is about.
 */
it('leaves an unconflicting grant alone', function (): void {
    $roles = app(Roles::class);
    $a = $roles->define('acme', 'reader');
    $b = $roles->define('acme', 'writer');

    $roles->assign('acme', 'user-2', $a->id);
    $roles->assign('acme', 'user-2', $b->id, GrantSource::Pushed);

    expect(app(SegregationOfDuties::class)->violationsFor('acme', 'user-2'))->toBe([]);
});
