<?php

declare(strict_types=1);

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * The config fallback in {@see PlatformRoot::environment()}, which only runs on a
 * deployment that never stamped `is_default`.
 *
 * It refuses a configured key that resolves to an environment a CUSTOMER owns, and that
 * refusal is a privilege boundary rather than a tidiness check: the platform's own people
 * are written into whatever this returns, so pointing `CBOX_ID_ENVIRONMENT_DEFAULT` at a
 * customer's environment would put every platform member inside that customer's tenant —
 * where its environment admins can set a password and sign in as them.
 *
 * It had no test. The predicate was `account_id === null`, and when that column was
 * deleted the model kept answering null for it, so the guard did not break loudly — it
 * quietly became true for every row and stopped refusing anything at all. A test here
 * would have failed the moment the column went.
 */
function tenantOwnedEnvironment(): Environment
{
    platformRootEnvironment();

    $environment = app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: 'Acme',
        ownerEmail: 'owner@acme.test',
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->environment;

    // Un-stamp the root so the config fallback is the path under test — with an
    // `is_default` row present, environment() never reaches it.
    Environment::query()->where('is_default', true)->update(['is_default' => false]);

    return $environment;
}

it('refuses a configured platform root that a customer owns', function (): void {
    $tenant = tenantOwnedEnvironment();

    expect($tenant->refresh()->project_id)->not->toBeNull('fixture must be customer-owned to test the refusal');

    config(['cbox-id.environments.default' => $tenant->slug]);

    expect(app(PlatformRoot::class)->environment())->toBeNull();
});

it('accepts a configured platform root that no customer owns', function (): void {
    tenantOwnedEnvironment();

    $unowned = Environment::query()->whereNull('project_id')->firstOrFail();

    config(['cbox-id.environments.default' => $unowned->slug]);

    expect(app(PlatformRoot::class)->environment()?->environmentKey())->toBe($unowned->id);
});

it('refuses a configured key with no environment row behind it', function (): void {
    tenantOwnedEnvironment();

    config(['cbox-id.environments.default' => 'no-such-environment']);

    expect(app(PlatformRoot::class)->environment())->toBeNull();
});
