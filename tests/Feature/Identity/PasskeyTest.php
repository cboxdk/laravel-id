<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Passkeys;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Identity\Exceptions\ClonedAuthenticator;
use Cbox\Id\Identity\Exceptions\CredentialAlreadyRegistered;
use Cbox\Id\Identity\Exceptions\UnknownCredential;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\Testing\FakeWebAuthnVerifier;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function fakeWebAuthn(FakeWebAuthnVerifier $fake): void
{
    app()->instance(WebAuthnVerifier::class, $fake);
}

it('registers a passkey credential', function (): void {
    fakeWebAuthn(new FakeWebAuthnVerifier(credentialId: 'cred_abc', registrationSignCount: 0));

    $credential = app(Passkeys::class)->register('user_1', 'challenge', '{}', name: 'MacBook');

    expect($credential->credential_id)->toBe('cred_abc')
        ->and($credential->user_id)->toBe('user_1')
        ->and(WebAuthnCredential::query()->count())->toBe(1);
});

it('refuses to reassign a credential already registered to another user', function (): void {
    fakeWebAuthn(new FakeWebAuthnVerifier(credentialId: 'cred_abc', registrationSignCount: 0));

    app(Passkeys::class)->register('user_victim', 'challenge', '{}', name: 'Victim key');

    // Attacker (a different authenticated user) presents a forged registration
    // carrying the victim's credential_id and their own public key.
    expect(fn () => app(Passkeys::class)->register('user_attacker', 'challenge', '{}'))
        ->toThrow(CredentialAlreadyRegistered::class);

    $row = WebAuthnCredential::query()->firstOrFail();
    expect(WebAuthnCredential::query()->count())->toBe(1)
        ->and($row->user_id)->toBe('user_victim');
});

it('allows the same user to re-register (rotate) their own credential', function (): void {
    fakeWebAuthn(new FakeWebAuthnVerifier(credentialId: 'cred_abc', registrationSignCount: 3));

    app(Passkeys::class)->register('user_1', 'challenge', '{}', name: 'Old name');
    $credential = app(Passkeys::class)->register('user_1', 'challenge', '{}', name: 'New name');

    expect($credential->name)->toBe('New name')
        ->and(WebAuthnCredential::query()->count())->toBe(1);
});

it('authenticates and advances the signature counter', function (): void {
    fakeWebAuthn(new FakeWebAuthnVerifier(credentialId: 'cred_abc', registrationSignCount: 1, assertionSignCount: 2));

    app(Passkeys::class)->register('user_1', 'challenge', '{}');
    $userId = app(Passkeys::class)->authenticate('cred_abc', 'challenge', '{}');

    expect($userId)->toBe('user_1')
        ->and(WebAuthnCredential::query()->firstOrFail()->sign_count)->toBe(2);
});

it('rejects a cloned authenticator (counter did not advance)', function (): void {
    fakeWebAuthn(new FakeWebAuthnVerifier(credentialId: 'cred_abc', registrationSignCount: 5, assertionSignCount: 5));

    app(Passkeys::class)->register('user_1', 'challenge', '{}');

    expect(fn () => app(Passkeys::class)->authenticate('cred_abc', 'challenge', '{}'))
        ->toThrow(ClonedAuthenticator::class);
});

it('rejects a replay at the same counter after a successful assertion', function (): void {
    // Register at 1, then two assertions both reporting counter 2. The first advances
    // the stored counter to 2; the second — a replay at that same counter — must be
    // rejected, because the atomic guard reads the already-advanced value.
    fakeWebAuthn(new FakeWebAuthnVerifier(credentialId: 'cred_abc', registrationSignCount: 1, assertionSignCount: 2));

    app(Passkeys::class)->register('user_1', 'challenge', '{}');

    expect(app(Passkeys::class)->authenticate('cred_abc', 'challenge', '{}'))->toBe('user_1')
        ->and(WebAuthnCredential::query()->firstOrFail()->sign_count)->toBe(2);

    expect(fn () => app(Passkeys::class)->authenticate('cred_abc', 'challenge', '{}'))
        ->toThrow(ClonedAuthenticator::class);

    // The stored counter is unchanged by the rejected replay.
    expect(WebAuthnCredential::query()->firstOrFail()->sign_count)->toBe(2);
});

it('rejects an unknown credential', function (): void {
    fakeWebAuthn(new FakeWebAuthnVerifier);

    expect(fn () => app(Passkeys::class)->authenticate('nope', 'challenge', '{}'))
        ->toThrow(UnknownCredential::class);
});
