<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Manifest\ManifestSyncResult;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    // Register a client in an environment and reconcile a single declared permission
    // for it — mirroring the pull/push path, where the app's environment is active
    // while its catalog is synced. Returns the declaring client's client_id.
    $this->declareInEnvironment = function (string $environment, string $key): string {
        return $this->runAsEnvironment($environment, function () use ($key): string {
            $clientId = $this->makeClient()->client->client_id;

            app(AppManifests::class)->sync($clientId, app(ManifestParser::class)->parse([
                'version' => '1',
                'permissions' => [['key' => $key, 'description' => 'declared '.$key]],
                'roles' => [],
            ]));

            return $clientId;
        });
    };
});

it('scopes a declared permission to its declaring client environment', function (): void {
    ($this->declareInEnvironment)('env_a', 'invoices:read');
    ($this->declareInEnvironment)('env_b', 'tickets:close');

    // env-A sees its own declared permission, never env-B's.
    $this->runAsEnvironment('env_a', function (): void {
        $names = Permission::query()->pluck('name')->all();

        expect($names)->toContain('invoices:read')
            ->and($names)->not->toContain('tickets:close');
    });

    // ...and symmetrically for env-B.
    $this->runAsEnvironment('env_b', function (): void {
        $names = Permission::query()->pluck('name')->all();

        expect($names)->toContain('tickets:close')
            ->and($names)->not->toContain('invoices:read');
    });
});

it('cannot resolve — nor bind — another environment declared permission id', function (): void {
    ($this->declareInEnvironment)('env_a', 'invoices:read');
    ($this->declareInEnvironment)('env_b', 'tickets:close');

    // The raw id of env-B's declared permission (read outside the scope).
    $envBId = $this->withoutEnvironmentScope(
        fn (): ?string => Permission::query()->where('name', 'tickets:close')->value('id'),
    );

    expect($envBId)->toBeString();

    // From env-A, resolving that id returns nothing — the role-bind read path
    // (Permission::query()->whereKey($id)) therefore refuses the cross-env grant.
    $resolved = $this->runAsEnvironment(
        'env_a',
        fn (): ?Permission => Permission::query()->whereKey($envBId)->first(),
    );

    expect($resolved)->toBeNull();
});

it('keeps a manual permission platform-global and visible from every environment', function (): void {
    // A manual permission (client_id null) is created with no environment stamp.
    Permission::query()->create([
        'client_id' => null,
        'name' => 'platform:manage',
        'description' => 'A shared, platform-global permission',
    ]);

    $seenFromA = $this->runAsEnvironment(
        'env_a',
        fn (): bool => Permission::query()->where('name', 'platform:manage')->exists(),
    );
    $seenFromB = $this->runAsEnvironment(
        'env_b',
        fn (): bool => Permission::query()->where('name', 'platform:manage')->exists(),
    );

    expect($seenFromA)->toBeTrue()
        ->and($seenFromB)->toBeTrue()
        ->and(Permission::query()->where('name', 'platform:manage')->value('environment_id'))->toBeNull();
});

it('stamps a declared permission with its client environment, derived from the client', function (): void {
    // Register the app in env_c.
    $clientId = $this->runAsEnvironment('env_c', fn (): string => $this->makeClient()->client->client_id);

    // Mirror the scheduled command + job: the command enumerates apps with tenancy
    // scope SUSPENDED, then each job re-enters the app's OWN environment before it
    // reconciles. The environment stamped on the permission is derived from the
    // client itself, resolved across the scope.
    $clientIds = $this->withoutEnvironmentScope(
        fn (): array => Client::query()->pluck('client_id')->all(),
    );
    expect($clientIds)->toContain($clientId);

    $result = $this->runAsEnvironment('env_c', fn (): ManifestSyncResult => app(AppManifests::class)->sync(
        $clientId,
        app(ManifestParser::class)->parse([
            'version' => '1',
            'permissions' => [['key' => 'reports:view', 'description' => 'View reports']],
            'roles' => [],
        ]),
    ));

    expect($result->permissionsDeclared)->toBe(1);

    $stamped = $this->withoutEnvironmentScope(
        fn (): ?string => Permission::query()->where('name', 'reports:view')->value('environment_id'),
    );

    expect($stamped)->toBe('env_c');

    // Visible from its own environment, invisible from a foreign one.
    expect($this->runAsEnvironment('env_c', fn (): bool => Permission::query()->where('name', 'reports:view')->exists()))->toBeTrue()
        ->and($this->runAsEnvironment('env_other', fn (): bool => Permission::query()->where('name', 'reports:view')->exists()))->toBeFalse();
});
