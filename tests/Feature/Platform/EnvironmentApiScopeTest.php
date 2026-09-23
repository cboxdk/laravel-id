<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

it('carries the tenancy-management scopes, each with a label and a description', function (): void {
    foreach ([
        'members:read', 'members:write', 'invitations:read', 'invitations:write',
        'roles:read', 'roles:write', 'apps:read', 'apps:write', 'apis:read', 'apis:write',
        'api_keys:read', 'api_keys:write', 'support:write',
    ] as $value) {
        $scope = EnvironmentApiScope::tryFrom($value);

        expect($scope)->not->toBeNull()
            ->and(EnvironmentApiScope::offerableValues())->toContain($value);
    }

    foreach (EnvironmentApiScope::cases() as $scope) {
        expect($scope->label())->not->toBe('')
            ->and($scope->description())->not->toBe('')
            ->and($scope->writes())->toBe(! str_ends_with($scope->value, ':read'));
    }
});

it('does not offer the reserved directory scopes on a new key', function (): void {
    expect(EnvironmentApiScope::DirectoriesRead->isReserved())->toBeTrue()
        ->and(EnvironmentApiScope::DirectoriesWrite->isReserved())->toBeTrue()
        ->and(EnvironmentApiScope::offerable())->not->toContain(EnvironmentApiScope::DirectoriesRead)
        ->and(EnvironmentApiScope::offerable())->not->toContain(EnvironmentApiScope::DirectoriesWrite)
        ->and(EnvironmentApiScope::offerableValues())->not->toContain('directories:read');
});

it('keeps honouring a reserved scope on a key that already holds it', function (): void {
    // Reserving a scope is a statement about NEW keys. A key issued with it before must
    // keep resolving, and keep answering for it, or reserving would be a silent revoke.
    $issued = app(EnvironmentApiKeys::class)->issue('env_a', 'legacy', [EnvironmentApiScope::DirectoriesRead->value]);

    $resolved = $this->runAsEnvironment('env_a', fn () => app(EnvironmentApiKeys::class)->resolve($issued->plaintext));

    expect($resolved?->can(EnvironmentApiScope::DirectoriesRead))->toBeTrue()
        ->and(EnvironmentApiScope::all())->toContain('directories:read');
});
