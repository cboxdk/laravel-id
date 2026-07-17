<?php

declare(strict_types=1);

use Cbox\Id\Identity\Exceptions\ClonedAuthenticator;
use Cbox\Id\Identity\Exceptions\UnknownCredential;
use Cbox\Id\Identity\Testing\FakeWebAuthnVerifier;
use Cbox\Id\Kernel\Audit\Testing\FakeAuditLog;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\DatabaseAccountPasskeys;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function passkeyMemberId(string $email = 'owner@acme.test'): string
{
    return app(AccountProvisioner::class)->provision(new AccountBlueprint(
        accountName: 'Acme',
        ownerEmail: $email,
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->member->id;
}

it('registers and authenticates an account passkey, returning the member id', function (): void {
    $passkeys = new DatabaseAccountPasskeys(new FakeWebAuthnVerifier(credentialId: 'cred_A', assertionSignCount: 5), new FakeAuditLog);
    $memberId = passkeyMemberId();

    $cred = $passkeys->register($memberId, 'reg-challenge', '{}', 'MacBook');
    expect($cred->account_member_id)->toBe($memberId)
        ->and($cred->credential_id)->toBe('cred_A')
        ->and($cred->name)->toBe('MacBook');

    $who = $passkeys->authenticate('cred_A', 'login-challenge', '{}');
    expect($who)->toBe($memberId)
        // The advanced counter is persisted.
        ->and($passkeys->credentialById('cred_A')->sign_count)->toBe(5);
});

it('rejects a cloned authenticator (non-increasing counter)', function (): void {
    // Registered at counter 9, but the assertion reports 9 → not strictly greater.
    $passkeys = new DatabaseAccountPasskeys(new FakeWebAuthnVerifier(credentialId: 'cred_B', registrationSignCount: 9, assertionSignCount: 9), new FakeAuditLog);
    $memberId = passkeyMemberId();
    $passkeys->register($memberId, 'reg', '{}');

    expect(fn () => $passkeys->authenticate('cred_B', 'login', '{}'))->toThrow(ClonedAuthenticator::class);
});

it('rejects an unknown credential', function (): void {
    $passkeys = new DatabaseAccountPasskeys(new FakeWebAuthnVerifier, new FakeAuditLog);

    expect(fn () => $passkeys->authenticate('nope', 'c', '{}'))->toThrow(UnknownCredential::class);
});

it('lists a member\'s passkeys and removes only their own', function (): void {
    $mine = passkeyMemberId('a@acme.test');
    $other = passkeyMemberId('b@other.test');
    $p = fn (string $cid) => new DatabaseAccountPasskeys(new FakeWebAuthnVerifier(credentialId: $cid), new FakeAuditLog);

    $c1 = $p('c1')->register($mine, 'r', '{}', 'Key 1');
    $p('cx')->register($other, 'r', '{}', 'Foreign');

    $repo = new DatabaseAccountPasskeys(new FakeWebAuthnVerifier, new FakeAuditLog);
    expect($repo->forMember($mine))->toHaveCount(1);

    // Can't remove another member's credential…
    expect($repo->remove($c1->id, $other))->toBeFalse()
        ->and($repo->forMember($mine))->toHaveCount(1);
    // …but can remove their own.
    expect($repo->remove($c1->id, $mine))->toBeTrue()
        ->and($repo->forMember($mine))->toHaveCount(0);
});
