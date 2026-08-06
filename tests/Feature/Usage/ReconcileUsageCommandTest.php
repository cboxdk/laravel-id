<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Usage\Contracts\ReconcilableScopes;
use Cbox\Id\Organization\DatabaseReconcilableScopes;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('reconciles every organization the ReconcilableScopes contract reports', function (): void {
    $a = $this->makeOrganization();
    $b = $this->makeOrganization();

    // The Usage kernel command resolves the metered scopes through the contract — the
    // Organization module binds the default, so the kernel never imports the model.
    $scopes = app(ReconcilableScopes::class);
    expect($scopes)->toBeInstanceOf(DatabaseReconcilableScopes::class)
        ->and($scopes->meteredOrganizationIds())->toEqualCanonicalizing([$a->id, $b->id]);

    $this->artisan('cbox-id:reconcile-usage')
        ->expectsOutputToContain('Reconciled 2 organization(s)')
        ->assertSuccessful();
});

it('reconciles only the named organization with --org', function (): void {
    $a = $this->makeOrganization();
    $this->makeOrganization();

    $this->artisan('cbox-id:reconcile-usage', ['--org' => $a->id])
        ->expectsOutputToContain('Reconciled 1 organization(s)')
        ->assertSuccessful();
});
