<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Kernel\Crypto\LibsodiumSecretBox;

it('seals and opens a value with matching context', function (): void {
    $box = app(SecretBox::class);

    $sealed = $box->seal('super-secret', 'connection:42');

    expect($sealed)->not->toBe('super-secret')
        ->and($box->open($sealed, 'connection:42'))->toBe('super-secret');
});

it('produces a different ciphertext each time (random nonce)', function (): void {
    $box = app(SecretBox::class);

    expect($box->seal('x', 'ctx'))->not->toBe($box->seal('x', 'ctx'));
});

it('refuses to open with a different context', function (): void {
    $box = app(SecretBox::class);
    $sealed = $box->seal('super-secret', 'connection:42');

    expect(fn () => $box->open($sealed, 'connection:99'))->toThrow(DecryptionFailed::class);
});

it('accepts the crypto key with or without the base64: prefix', function (): void {
    $raw = base64_encode(random_bytes(32));

    // Seal under the raw base64 key.
    config(['cbox-id.crypto.key' => $raw]);
    app()->forgetInstance(SecretBox::class);
    $sealed = app(SecretBox::class)->seal('super-secret', 'ctx');

    // The identical key carrying Laravel's conventional `base64:` prefix must
    // decode to the same bytes and open the ciphertext.
    config(['cbox-id.crypto.key' => 'base64:'.$raw]);
    app()->forgetInstance(SecretBox::class);

    expect(app(SecretBox::class)->open($sealed, 'ctx'))->toBe('super-secret');
});

it('refuses to open a tampered ciphertext', function (): void {
    $box = app(SecretBox::class);
    $sealed = $box->seal('super-secret', 'ctx');
    $tampered = substr($sealed, 0, -4).'AAAA';

    expect(fn () => $box->open($tampered, 'ctx'))->toThrow(DecryptionFailed::class);
});

/**
 * Frozen envelopes — the compatibility contract for everything already at rest.
 *
 * Every other test here seals and opens in the same process, so it moves BOTH sides
 * together: change the nonce length, add a version byte, swap base64url for base64,
 * reorder nonce and tag, and a round-trip test still passes while every secret already
 * in every customer's database becomes permanently unreadable. This box seals private
 * signing keys, directory credentials and vault secrets — there is no recovering from
 * that, and no error until a customer tries to sign in.
 *
 * These two strings were produced by libsodium and checked in. They are not an external
 * spec vector; they are OUR envelope format, pinned. A change that breaks them is a
 * migration, not a refactor — and the failure below is the reminder to write one.
 *
 * The empty-plaintext case is here because it is the shortest legal envelope (24-byte
 * nonce + 16-byte tag) and therefore the one an off-by-one length check gets wrong.
 */
it('opens envelopes sealed by an earlier release', function (): void {
    $box = new LibsodiumSecretBox(str_repeat("\x2b", 32));

    expect($box->open('BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHK-76KrVnrDnV7cHhNQC2xbHYKNR0acDwlUso4FbNSNIN1fDQPq2hj6NrLg8', 'vault:acme'))
        ->toBe('signing-key:MIIEvQIBADANBgkq')
        ->and($box->open('BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHGItE0nVVIH5ZEco81OIiHg'))
        ->toBe('');
});

/**
 * The same frozen envelope under the wrong context, proving the AAD is genuinely bound
 * into the tag rather than merely compared. A ciphertext lifted from one tenant's row
 * and pasted into another's does not open.
 */
it('will not open a frozen envelope under a different context', function (): void {
    $box = new LibsodiumSecretBox(str_repeat("\x2b", 32));

    expect(fn () => $box->open('BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHK-76KrVnrDnV7cHhNQC2xbHYKNR0acDwlUso4FbNSNIN1fDQPq2hj6NrLg8', 'vault:other'))
        ->toThrow(DecryptionFailed::class);
});
