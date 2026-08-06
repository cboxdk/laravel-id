<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Kernel\Crypto\Testing\FakeSecretBox;

it('round-trips a secret and enforces context binding', function (): void {
    $box = new FakeSecretBox;

    $sealed = $box->seal('super-secret', 'record:42');

    expect($box->open($sealed, 'record:42'))->toBe('super-secret');

    // Wrong context fails, exactly like the real AEAD.
    $box->open($sealed, 'record:99');
})->throws(DecryptionFailed::class);
