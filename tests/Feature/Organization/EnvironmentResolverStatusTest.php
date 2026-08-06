<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['cbox-id.environments.base_domains' => ['cboxid.com']]));

function acmeEnvironment(): Environment
{
    platformRootEnvironment();

    return app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: 'Acme',
        ownerEmail: 'owner@acme.test',
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->environment; // slug 'acme'
}

it('resolves an active environment by its base-domain subdomain', function (): void {
    $env = acmeEnvironment();

    expect(app(EnvironmentResolver::class)->resolveForHost('acme.cboxid.com')?->environmentKey())
        ->toBe($env->id);
});

it('stops resolving when the owning account is suspended, and resumes on reactivation', function (): void {
    $env = acmeEnvironment();
    $resolver = app(EnvironmentResolver::class);

    expect($resolver->resolveForHost('acme.cboxid.com'))->not->toBeNull();

    suspendOwnerOf($env);

    // Read it back rather than trusting the write. The resolver compares
    // `organizations.status` to the literal 'active', and an enum whose suspended case
    // serialises to something else would leave this test asserting that a suspension
    // nobody performed had no effect.
    expect(app(PlatformRoot::class)->run(
        fn (): mixed => DB::table('organizations')->where('id', ownerOrganizationOf($env))->value('status'),
    ))->not->toBe('active');
    expect($resolver->resolveForHost('acme.cboxid.com'))->toBeNull();

    reactivateOwnerOf($env);
    expect($resolver->resolveForHost('acme.cboxid.com'))->not->toBeNull();
});

it('stops resolving a suspended environment even if its account is active', function (): void {
    $env = acmeEnvironment();
    $env->forceFill(['status' => 'suspended'])->save();

    expect(app(EnvironmentResolver::class)->resolveForHost('acme.cboxid.com'))->toBeNull();
});

it('never maps an unknown host to any environment', function (): void {
    acmeEnvironment();

    // A spoofed / unmapped host is not resolved to a customer plane.
    expect(app(EnvironmentResolver::class)->resolveForHost('evil.attacker.com'))->toBeNull()
        ->and(app(EnvironmentResolver::class)->resolveForHost('acme.cboxid.com.evil.com'))->toBeNull();
});
