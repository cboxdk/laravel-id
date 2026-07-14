<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;

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
