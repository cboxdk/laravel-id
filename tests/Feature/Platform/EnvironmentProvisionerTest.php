<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\EnvironmentProvisioner;
use Cbox\Id\Platform\ValueObjects\EnvironmentBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function blueprint(string $name = 'Acme IdP', string $email = 'owner@acme.test'): EnvironmentBlueprint
{
    return new EnvironmentBlueprint(
        name: $name,
        ownerEmail: $email,
        ownerName: 'Acme Owner',
        ownerPassword: 'supersecret123',
        organizationName: 'Acme Inc',
    );
}

it('provisions a new environment with a bootstrapped owner and organization', function (): void {
    $result = app(EnvironmentProvisioner::class)->provision(blueprint());

    expect($result->environment->slug)->toBe('acme-idp')
        ->and($result->environment->status)->toBe('active')
        ->and($result->owner->email)->toBe('owner@acme.test')
        ->and(Environment::query()->whereKey($result->environment->id)->exists())->toBeTrue();

    // The owner + org live INSIDE the new environment, and the owner is its admin.
    app(EnvironmentContext::class)->runAs($result->environment, function () use ($result): void {
        $org = Organization::query()->find($result->organization->id);
        expect($org)->not->toBeNull()
            ->and($org->environment_id)->toBe($result->environment->id);

        $membership = app(Memberships::class)->of($result->organization->id, $result->owner->id);
        expect($membership)->not->toBeNull()
            ->and($membership->role)->toBe('owner');
    });
});

it('isolates the new environment from the ambient scope', function (): void {
    $result = app(EnvironmentProvisioner::class)->provision(blueprint());

    // In the ambient (default) environment, the provisioned org is not visible —
    // it belongs to a different plane entirely.
    expect(Organization::query()->where('id', $result->organization->id)->exists())->toBeFalse();
});

it('gives each provisioned environment a unique routing slug', function (): void {
    $a = app(EnvironmentProvisioner::class)->provision(blueprint('Acme IdP', 'a@acme.test'));
    $b = app(EnvironmentProvisioner::class)->provision(blueprint('Acme IdP', 'b@acme.test'));

    expect($a->environment->slug)->toBe('acme-idp')
        ->and($b->environment->slug)->toBe('acme-idp-2')
        ->and($a->environment->id)->not->toBe($b->environment->id);
});
