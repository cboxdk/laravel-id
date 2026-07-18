<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

it('issues a cbid_env_ key and resolves it only inside its own environment', function (): void {
    $issued = app(EnvironmentApiKeys::class)->issue('env_a', 'CI', [
        EnvironmentApiScope::OrganizationsRead->value,
        EnvironmentApiScope::UsersRead->value,
    ]);

    expect($issued->plaintext)->toStartWith('cbid_env_')
        ->and($issued->key->prefix)->toBe(substr($issued->plaintext, 0, 13))
        ->and($issued->key->environment_id)->toBe('env_a');

    // Resolves on its own environment's host (the request already resolved env_a).
    $resolved = $this->runAsEnvironment('env_a', fn () => app(EnvironmentApiKeys::class)->resolve($issued->plaintext));
    expect($resolved)->not->toBeNull()
        ->and($resolved->id)->toBe($issued->key->id)
        ->and($resolved->can(EnvironmentApiScope::OrganizationsRead))->toBeTrue()
        ->and($resolved->can(EnvironmentApiScope::OrganizationsWrite))->toBeFalse()
        ->and($resolved->last_used_at)->not->toBeNull();

    // The SAME token on a DIFFERENT environment's host does not resolve at all —
    // the hard scope makes a cross-environment key invisible, not merely rejected.
    $onWrongHost = $this->runAsEnvironment('env_b', fn () => app(EnvironmentApiKeys::class)->resolve($issued->plaintext));
    expect($onWrongHost)->toBeNull();
});

it('stores only the hash, never the plaintext', function (): void {
    $issued = app(EnvironmentApiKeys::class)->issue('env_a', 'CI', EnvironmentApiScope::all());

    expect($issued->key->token_hash)->toBe(hash('sha256', $issued->plaintext))
        ->and($issued->key->getAttribute('token_hash'))->not->toBe($issued->plaintext)
        // token_hash is hidden from array/JSON output.
        ->and($issued->key->toArray())->not->toHaveKey('token_hash');
});

it('refuses a revoked or expired key', function (): void {
    $keys = app(EnvironmentApiKeys::class);

    $revoked = $keys->issue('env_a', 'old', EnvironmentApiScope::all());
    $keys->revoke('env_a', $revoked->key->id);

    $expired = $keys->issue('env_a', 'stale', EnvironmentApiScope::all(), now()->subMinute());

    $this->runAsEnvironment('env_a', function () use ($keys, $revoked, $expired): void {
        expect($keys->resolve($revoked->plaintext))->toBeNull()
            ->and($keys->resolve($expired->plaintext))->toBeNull();
    });
});

it('rejects a token without the cbid_env_ prefix without a query', function (): void {
    expect(app(EnvironmentApiKeys::class)->resolve('cbid_acc_notours'))->toBeNull()
        ->and(app(EnvironmentApiKeys::class)->resolve('garbage'))->toBeNull();
});

it('lists an environment\'s keys newest-first and never another environment\'s', function (): void {
    $keys = app(EnvironmentApiKeys::class);

    $first = $keys->issue('env_a', 'first', EnvironmentApiScope::all());
    $second = $keys->issue('env_a', 'second', EnvironmentApiScope::all());
    $keys->issue('env_b', 'other', EnvironmentApiScope::all());

    $list = $keys->forEnvironment('env_a');

    expect($list)->toHaveCount(2)
        ->and($list->first()?->id)->toBe($second->key->id)
        ->and($list->last()?->id)->toBe($first->key->id);
});
