<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\MasterKeyRing;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Kernel\Crypto\LibsodiumSecretBox;
use Cbox\Id\Kernel\Crypto\ValueObjects\MasterKey;
use Cbox\Id\Kernel\Crypto\ValueObjects\MasterKeySet;

/*
 * The versioned keyring behind the SecretBox. Two envelope formats must open forever:
 * the untagged one every release up to 1.21 wrote (pinned in SecretBoxTest), and the
 * v1 one that names its key. Both are pinned here against fixed keys.
 */

/** The 0x2b key the frozen envelopes in SecretBoxTest were sealed under. */
const FROZEN_KEY = "\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b\x2b";

/** An untagged (≤ 1.21) envelope of 'signing-key:MIIEvQIBADANBgkq' under FROZEN_KEY, context 'vault:acme'. */
const FROZEN_UNTAGGED = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHK-76KrVnrDnV7cHhNQC2xbHYKNR0acDwlUso4FbNSNIN1fDQPq2hj6NrLg8';

/** The same plaintext and context sealed v1 under FROZEN_KEY by this release. */
const FROZEN_V1 = 'v1.4260771134273ee3.aTVgDIez9qcBVjjK2XqmBJGr4HbWkbb25_9fIJ4DNYgbEnBPUjUE4rSsnK5c6oG8V-Sl3xfaEmMHQ9hetcYZsFSXCC0';

function freshKey(): MasterKey
{
    return new MasterKey(random_bytes(32));
}

it('derives a stable key id that is an HMAC of a fixed label, never the key', function (): void {
    // Computed independently (Python hmac/hashlib) over the same label.
    expect((new MasterKey(FROZEN_KEY))->id)->toBe('4260771134273ee3')
        ->and((new MasterKey(str_repeat("\x07", 32)))->id)->toBe('7a99f40f1c69fe18')
        ->and(print_r(new MasterKey(FROZEN_KEY), true))->not->toContain(FROZEN_KEY)
        ->and(var_export((new MasterKey(FROZEN_KEY))->id, true))->not->toContain(base64_encode(FROZEN_KEY));
});

it('opens a frozen v1 envelope, which names its key', function (): void {
    $box = new LibsodiumSecretBox(FROZEN_KEY);

    expect($box->open(FROZEN_V1, 'vault:acme'))->toBe('signing-key:MIIEvQIBADANBgkq')
        ->and($box->sealedUnder(FROZEN_V1))->toBe('4260771134273ee3')
        ->and($box->isCurrent(FROZEN_V1))->toBeTrue();
});

it('seals everything new as v1 under the current key', function (): void {
    $box = new LibsodiumSecretBox(FROZEN_KEY);
    $sealed = $box->seal('x', 'ctx');

    expect($sealed)->toStartWith('v1.4260771134273ee3.')
        ->and($box->currentPrefix())->toBe('v1.4260771134273ee3.')
        ->and($box->open($sealed, 'ctx'))->toBe('x');
});

it('opens both frozen formats after a rotation, with the old key kept as a previous key', function (): void {
    $rotated = new LibsodiumSecretBox(new MasterKeySet(freshKey(), [new MasterKey(FROZEN_KEY)]));

    expect($rotated->open(FROZEN_UNTAGGED, 'vault:acme'))->toBe('signing-key:MIIEvQIBADANBgkq')
        ->and($rotated->open(FROZEN_V1, 'vault:acme'))->toBe('signing-key:MIIEvQIBADANBgkq')
        ->and($rotated->isCurrent(FROZEN_V1))->toBeFalse()
        ->and($rotated->sealedUnder(FROZEN_UNTAGGED))->toBeNull();
});

it('names the missing key when a v1 envelope was sealed under a key that is no longer configured', function (): void {
    $withoutOldKey = new LibsodiumSecretBox(new MasterKeySet(freshKey()));

    expect(fn () => $withoutOldKey->open(FROZEN_V1, 'vault:acme'))
        ->toThrow(DecryptionFailed::class, '4260771134273ee3');
});

it('refuses an untagged envelope no configured key opens, and a wrong context under the right key', function (): void {
    expect(fn () => (new LibsodiumSecretBox(new MasterKeySet(freshKey(), [freshKey()])))->open(FROZEN_UNTAGGED, 'vault:acme'))
        ->toThrow(DecryptionFailed::class)
        ->and(fn () => (new LibsodiumSecretBox(FROZEN_KEY))->open(FROZEN_V1, 'vault:other'))
        ->toThrow(DecryptionFailed::class);
});

it('refuses an envelope version it does not know, and a truncated tag', function (): void {
    $box = new LibsodiumSecretBox(FROZEN_KEY);

    expect(fn () => $box->open('v9.4260771134273ee3.AAAA', ''))->toThrow(DecryptionFailed::class, 'version')
        ->and(fn () => $box->open('v1..AAAA', ''))->toThrow(DecryptionFailed::class)
        ->and(fn () => $box->open('v1.4260771134273ee3.', ''))->toThrow(DecryptionFailed::class);
});

it('rewraps onto the current key, keeps the context binding, and leaves a current value alone', function (): void {
    $current = freshKey();
    $ring = new LibsodiumSecretBox(new MasterKeySet($current, [new MasterKey(FROZEN_KEY)]));

    $fromUntagged = $ring->rewrap(FROZEN_UNTAGGED, 'vault:acme');
    $fromV1 = $ring->rewrap(FROZEN_V1, 'vault:acme');

    expect($fromUntagged)->toStartWith('v1.'.$current->id.'.')
        ->and($fromV1)->toStartWith('v1.'.$current->id.'.')
        ->and($ring->open($fromUntagged, 'vault:acme'))->toBe('signing-key:MIIEvQIBADANBgkq')
        ->and($ring->rewrap($fromV1, 'vault:acme'))->toBe($fromV1)
        ->and(fn () => $ring->open($fromV1, 'vault:other'))->toThrow(DecryptionFailed::class);

    // And the new key alone opens it — the old one can now be dropped.
    expect((new LibsodiumSecretBox(new MasterKeySet($current)))->open($fromV1, 'vault:acme'))
        ->toBe('signing-key:MIIEvQIBADANBgkq');
});

it('reads previous keys from config as a comma-separated list, with or without base64:', function (): void {
    $old = base64_encode(FROZEN_KEY);
    $older = base64_encode(str_repeat("\x07", 32));
    $current = base64_encode(random_bytes(32));

    $set = MasterKeySet::fromConfig($current, " base64:{$old} , {$older},,{$current}");

    // The current key re-listed as a previous one is dropped, not doubled.
    expect($set->previousIds())->toBe(['4260771134273ee3', '7a99f40f1c69fe18'])
        ->and(MasterKeySet::fromConfig($current, [$old])->previousIds())->toBe(['4260771134273ee3'])
        ->and(MasterKeySet::fromConfig($current)->previous)->toBe([]);
});

it('refuses a malformed previous key or a missing current key', function (): void {
    expect(fn () => MasterKeySet::fromConfig(base64_encode(random_bytes(32)), 'not base64!'))
        ->toThrow(CryptoConfigurationException::class, 'CBOX_ID_CRYPTO_PREVIOUS_KEYS')
        ->and(fn () => MasterKeySet::fromConfig(null, base64_encode(FROZEN_KEY)))
        ->toThrow(CryptoConfigurationException::class, 'not configured');
});

it('binds the configured keyring to the container', function (): void {
    $current = base64_encode(random_bytes(32));
    config(['cbox-id.crypto.key' => $current, 'cbox-id.crypto.previous_keys' => base64_encode(FROZEN_KEY)]);
    app()->forgetInstance(SecretBox::class);

    $ring = app(MasterKeyRing::class);

    expect($ring)->toBe(app(SecretBox::class))
        ->and($ring->previousKeyIds())->toBe(['4260771134273ee3'])
        ->and(app(SecretBox::class)->open(FROZEN_UNTAGGED, 'vault:acme'))->toBe('signing-key:MIIEvQIBADANBgkq');
});
