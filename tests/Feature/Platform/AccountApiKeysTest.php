<?php

declare(strict_types=1);

use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\AccountApiKeys;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Enums\AccountRole;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function anAccount(string $email = 'owner@acme.test'): string
{
    return app(AccountProvisioner::class)->provision(new AccountBlueprint(
        accountName: 'Acme',
        ownerEmail: $email,
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->account->id;
}

it('issues a key, returns the plaintext once, and stores only its hash', function (): void {
    $keys = app(AccountApiKeys::class);

    $issued = $keys->issue(anAccount(), 'CI deploy', AccountRole::Admin);

    expect($issued->plaintext)->toStartWith('cbid_acc_')
        ->and($issued->key->role)->toBe(AccountRole::Admin)
        ->and($issued->key->prefix)->toBe(substr($issued->plaintext, 0, 12))
        // Plaintext is never persisted — only its hash.
        ->and($issued->key->token_hash)->toBe(hash('sha256', $issued->plaintext))
        ->and($issued->key->getAttributes())->not->toContain($issued->plaintext);
});

it('resolves a valid token to its key and records use', function (): void {
    $keys = app(AccountApiKeys::class);
    $issued = $keys->issue(anAccount(), 'Key', AccountRole::Developer);

    $resolved = $keys->resolve($issued->plaintext);

    expect($resolved)->not->toBeNull()
        ->and($resolved->id)->toBe($issued->key->id)
        ->and($resolved->last_used_at)->not->toBeNull();
});

it('rejects a valid key once its account is suspended', function (): void {
    $keys = app(AccountApiKeys::class);
    $accountId = anAccount();
    $issued = $keys->issue($accountId, 'Key', AccountRole::Admin);

    expect($keys->resolve($issued->plaintext))->not->toBeNull();

    // The platform's off-switch: suspending the account kills its keys immediately.
    app(Accounts::class)->suspend($accountId);
    expect($keys->resolve($issued->plaintext))->toBeNull();

    // Reactivation restores it.
    app(Accounts::class)->reactivate($accountId);
    expect($keys->resolve($issued->plaintext))->not->toBeNull();
});

it('rejects unknown, revoked, and expired tokens', function (): void {
    $keys = app(AccountApiKeys::class);
    $accountId = anAccount();

    // Wrong-shape (no prefix) and right-prefix-but-unknown both resolve to null.
    expect($keys->resolve('bearer-nonsense'))->toBeNull()
        ->and($keys->resolve('cbid_acc_notarealtoken'))->toBeNull();

    // Revoked.
    $revoked = $keys->issue($accountId, 'Revoked', AccountRole::Admin);
    $keys->revoke($revoked->key->id);
    expect($keys->resolve($revoked->plaintext))->toBeNull();

    // Expired.
    $expired = $keys->issue($accountId, 'Expired', AccountRole::Admin, now()->subMinute());
    expect($keys->resolve($expired->plaintext))->toBeNull();
});

it('lists an account\'s keys newest first', function (): void {
    $keys = app(AccountApiKeys::class);
    $accountId = anAccount();

    $keys->issue($accountId, 'First', AccountRole::Viewer);
    $keys->issue($accountId, 'Second', AccountRole::Admin);
    // A different account's key must not leak in.
    $keys->issue(anAccount('other@x.test'), 'Foreign', AccountRole::Admin);

    $list = $keys->forAccount($accountId);

    expect($list)->toHaveCount(2)
        ->and($list->pluck('name')->all())->toBe(['Second', 'First']);
});
