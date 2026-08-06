<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Platform\Contracts\OrganizationApiKeys;
use Cbox\Id\Platform\Exceptions\OrganizationSuspended;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\ProvisionedTenant;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Suspending an organization is the widest revocation the platform has: it is the
 * off-switch for a delinquent or abusive customer, and it has to reach every plane the
 * customer touches at once — the hosts their environments answer on, the keys that drive
 * the management API, and their ability to be sold anything further.
 *
 * IT IS TESTED HERE AS ONE ACT because each half lives somewhere else and each half was
 * broken on its own during this refactor. The resolver's cache kept serving suspended
 * hosts, because the invalidation had been the deleted account writer's job and moved
 * nowhere. The provisioner kept selling products and environments, because the old
 * provisioner locked the account and refused and only the project check came across. Both
 * were invisible from the modules that owned them; both are obvious from here.
 *
 * `Deleted` gets the same coverage as `Suspended` throughout. It is written by `archive()`,
 * it reads like a soft-delete marker, and every gate that pattern-matched on `Suspended`
 * alone has let it through at least once.
 */
function suspendableTenant(string $name = 'Acme'): ProvisionedTenant
{
    platformRootEnvironment();

    return app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: $name,
        ownerEmail: strtolower($name).'@test.test',
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
        environmentLimit: 5,
    ));
}

/** @return array{0: ProvisionedTenant, 1: string} the tenant, and a live API key's plaintext */
function suspendableTenantWithKey(): array
{
    $tenant = suspendableTenant();

    $plaintext = app(PlatformRoot::class)->run(
        fn (): string => app(OrganizationApiKeys::class)
            ->issue($tenant->organization->id, 'CI', MembershipRole::Admin)
            ->plaintext,
    );

    return [$tenant, (string) $plaintext];
}

it('cuts the host, the key and the chequebook in one act', function (): void {
    [$tenant, $plaintext] = suspendableTenantWithKey();

    $resolver = app(EnvironmentResolver::class);
    $keys = app(OrganizationApiKeys::class);
    $host = $tenant->environment->slug.'.cboxid.com';

    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);

    // Everything works first, so the assertions below cannot pass by never having worked.
    expect($resolver->resolveForHost($host))->not->toBeNull()
        ->and($keys->resolve($plaintext))->not->toBeNull();

    app(PlatformRoot::class)->run(
        fn () => app(Organizations::class)->suspend($tenant->organization->id, 'op_test'),
    );

    // The host, on the very NEXT request — not when a cache TTL happens to lapse.
    expect($resolver->resolveForHost($host))->toBeNull()
        // The management API, so a suspended customer cannot keep driving it.
        ->and($keys->resolve($plaintext))->toBeNull();

    // And nothing further can be sold to them.
    expect(fn () => app(TenantProvisioner::class)->addProject($tenant->organization, 'Blocked'))
        ->toThrow(OrganizationSuspended::class);

    expect(fn () => app(TenantProvisioner::class)->addEnvironment($tenant->project, 'Blocked'))
        ->toThrow(OrganizationSuspended::class);
})->group('security');

it('gives all of it back on reactivation', function (): void {
    [$tenant, $plaintext] = suspendableTenantWithKey();

    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);
    $host = $tenant->environment->slug.'.cboxid.com';

    app(PlatformRoot::class)->run(
        fn () => app(Organizations::class)->suspend($tenant->organization->id, 'op_test'),
    );
    expect(app(EnvironmentResolver::class)->resolveForHost($host))->toBeNull();

    app(PlatformRoot::class)->run(
        fn () => app(Organizations::class)->reactivate($tenant->organization->id, 'op_test'),
    );

    // Just as promptly as it was taken away. A refusal is never cached, so nothing has to
    // lapse before service returns.
    expect(app(EnvironmentResolver::class)->resolveForHost($host))->not->toBeNull()
        ->and(app(OrganizationApiKeys::class)->resolve($plaintext))->not->toBeNull()
        ->and(app(TenantProvisioner::class)->addProject($tenant->organization, 'Allowed')->name)->toBe('Allowed');
})->group('security');

it('treats an archived organization exactly as a suspended one', function (): void {
    [$tenant, $plaintext] = suspendableTenantWithKey();

    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);
    $host = $tenant->environment->slug.'.cboxid.com';

    app(PlatformRoot::class)->run(
        fn () => app(Organizations::class)->archive($tenant->organization->id, 'op_test'),
    );

    // `Deleted`, not `Suspended` — every one of these gates has to ask the enum rather
    // than compare against a single case.
    expect(app(EnvironmentResolver::class)->resolveForHost($host))->toBeNull()
        ->and(app(OrganizationApiKeys::class)->resolve($plaintext))->toBeNull();

    expect(fn () => app(TenantProvisioner::class)->addProject($tenant->organization, 'Blocked'))
        ->toThrow(OrganizationSuspended::class);

    expect(fn () => app(TenantProvisioner::class)->addEnvironment($tenant->project, 'Blocked'))
        ->toThrow(OrganizationSuspended::class);
})->group('security');

it('leaves another organization untouched', function (): void {
    [$suspended, $suspendedKey] = suspendableTenantWithKey();
    $bystander = suspendableTenant('Globex');

    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);

    app(PlatformRoot::class)->run(
        fn () => app(Organizations::class)->suspend($suspended->organization->id, 'op_test'),
    );

    // The invalidation enumerates the environments of ONE organization. A blunter
    // implementation — flushing the cache, or walking the hierarchy — would pass every
    // assertion above and take the whole platform's cached routing with it each time an
    // operator suspended a single customer.
    expect(app(EnvironmentResolver::class)->resolveForHost($bystander->environment->slug.'.cboxid.com'))
        ->not->toBeNull()
        ->and(app(OrganizationApiKeys::class)->resolve($suspendedKey))->toBeNull()
        ->and(app(TenantProvisioner::class)->addProject($bystander->organization, 'Fine')->name)->toBe('Fine');
})->group('security');
