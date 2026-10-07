<?php

declare(strict_types=1);

use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Contracts\ManagementScopes;
use Cbox\Id\Platform\Contracts\OrganizationApiKeys;
use Cbox\Id\Platform\EnumManagementScopes;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Cbox\Id\Platform\Exceptions\UnknownApiKeyScope;
use Cbox\Id\Platform\Models\EnvironmentApiKey;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\KeyProvenance;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/** An organization that owns products, provisioned in the platform root. */
function provenanceOrganization(string $name): string
{
    platformRootEnvironment();

    return app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: $name,
        ownerEmail: strtolower($name).'@provenance.test',
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->organization->id;
}

/**
 * @template TReturn
 *
 * @param  Closure(): TReturn  $callback
 * @return TReturn
 */
function inPlatformRoot(Closure $callback): mixed
{
    return app(PlatformRoot::class)->run($callback);
}

/*
| Management keys that can be minted by other keys: a scope vocabulary that refuses what
| it does not know, a record of who minted each key and from which, and a prefix the host
| may name its plane by.
*/

it('refuses to issue an environment key with a scope nothing recognises', function (): void {
    app(EnvironmentApiKeys::class)->issue('env_a', 'CI', [EnvironmentApiScope::AppsRead->value, 'apps:everything']);
})->throws(UnknownApiKeyScope::class, 'apps:everything');

it('lets a host add scopes for its own endpoints by rebinding the vocabulary', function (): void {
    app()->singleton(ManagementScopes::class, fn (): ManagementScopes => new class extends EnumManagementScopes
    {
        public function knows(string $scope): bool
        {
            return $scope === 'webhooks:write' || parent::knows($scope);
        }
    });

    $issued = app(EnvironmentApiKeys::class)->issue('env_a', 'Hooks', ['webhooks:write', EnvironmentApiScope::AppsRead->value]);

    expect($issued->key->can('webhooks:write'))->toBeTrue()
        ->and($issued->key->can(EnvironmentApiScope::AppsRead))->toBeTrue()
        ->and($issued->key->can('webhooks:read'))->toBeFalse();
});

it('records who minted an environment key and from which key', function (): void {
    $keys = app(EnvironmentApiKeys::class);
    $parent = $keys->issue('env_a', 'Parent', [EnvironmentApiScope::AppsWrite->value]);

    $child = $keys->issue('env_a', 'Child', [EnvironmentApiScope::AppsWrite->value], null, new KeyProvenance(
        createdByType: 'environment_key',
        createdById: $parent->key->id,
        parentKeyId: $parent->key->id,
        description: 'Deploy bot for staging',
        stepUpPolicy: ['require_approval' => ['min_danger' => 'critical']],
    ));

    $stored = $this->runAsEnvironment('env_a', fn () => EnvironmentApiKey::query()->whereKey($child->key->id)->firstOrFail());

    expect($stored->parent_key_id)->toBe($parent->key->id)
        ->and($stored->created_by_type)->toBe('environment_key')
        ->and($stored->description)->toBe('Deploy bot for staging')
        ->and($stored->step_up_policy)->toBe(['require_approval' => ['min_danger' => 'critical']])
        ->and($parent->key->parent_key_id)->toBeNull();
});

it('records provenance and optional scopes on an organization key, bounded by its role', function (): void {
    $organizationId = provenanceOrganization('Provenance');
    $keys = app(OrganizationApiKeys::class);

    $narrow = inPlatformRoot(fn () => $keys->issue($organizationId, 'Narrow', MembershipRole::Admin, null, ['environments:read'], new KeyProvenance(
        createdByType: 'user',
        createdById: 'usr_1',
    )));
    $role = inPlatformRoot(fn () => $keys->issue($organizationId, 'Role only', MembershipRole::Admin));

    expect($narrow->key->permits('environments:read'))->toBeTrue()
        ->and($narrow->key->permits('environments:write'))->toBeFalse()
        ->and($narrow->key->created_by_id)->toBe('usr_1')
        ->and($role->key->scopes)->toBeNull()
        ->and($role->key->permits('environments:write'))->toBeTrue();
});

it('mints and resolves organization keys under a configured prefix, and only that prefix', function (): void {
    config(['cbox-id.management_keys.organization_prefix' => 'cbid_ws_']);
    $organizationId = provenanceOrganization('Prefix');
    $keys = app(OrganizationApiKeys::class);

    $issued = inPlatformRoot(fn () => $keys->issue($organizationId, 'Workspace', MembershipRole::Admin));

    expect($issued->plaintext)->toStartWith('cbid_ws_')
        ->and($issued->key->prefix)->toBe(substr($issued->plaintext, 0, 11))
        ->and($keys->resolve($issued->plaintext)?->id)->toBe($issued->key->id)
        ->and($keys->resolve('cbid_org_'.substr($issued->plaintext, 8)))->toBeNull();
});

it('falls back to cbid_org_ when the configured prefix is malformed', function (string $prefix): void {
    config(['cbox-id.management_keys.organization_prefix' => $prefix]);
    $organizationId = provenanceOrganization('Fallback');

    $issued = inPlatformRoot(fn () => app(OrganizationApiKeys::class)->issue($organizationId, 'Key', MembershipRole::Admin));

    expect($issued->plaintext)->toStartWith('cbid_org_');
})->with(['no-underscore', 'CBID_WS_', 'cbid_ws', '', 'cbid__']);
