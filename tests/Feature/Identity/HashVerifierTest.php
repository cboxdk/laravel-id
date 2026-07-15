<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\Hashing\HashVerifierRegistry;
use Cbox\Id\Identity\Hashing\NativePasswordVerifier;

it('verifies real bcrypt and argon2id hashes through PHP password_verify', function (): void {
    $verifier = new NativePasswordVerifier(PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);

    $bcrypt = password_hash('correct-horse', PASSWORD_BCRYPT);
    $argon = password_hash('correct-horse', PASSWORD_ARGON2ID);

    expect($verifier->supports($bcrypt))->toBeTrue()
        ->and($verifier->supports($argon))->toBeTrue()
        ->and($verifier->verify('correct-horse', $bcrypt))->toBeTrue()
        ->and($verifier->verify('wrong', $bcrypt))->toBeFalse()
        ->and($verifier->verify('correct-horse', $argon))->toBeTrue();
});

it('flags a bcrypt hash for rehash when the platform target is argon2id, but not an up-to-date argon2id hash', function (): void {
    $verifier = new NativePasswordVerifier(PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);

    expect($verifier->needsRehash(password_hash('pw', PASSWORD_BCRYPT)))->toBeTrue()
        ->and($verifier->needsRehash(password_hash('pw', PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1])))->toBeFalse();
});

it('is deny-by-default: an unknown format is unsupported and never verifies', function (): void {
    $verifier = new NativePasswordVerifier(PASSWORD_BCRYPT, ['cost' => 12]);

    // LDAP {SSHA}, raw md5, raw sha1 — none are native password_hash formats.
    $ssha = '{SSHA}'.base64_encode('digestsalt');
    $md5 = md5('secret');
    $sha1 = 'sha1$'.sha1('secret');

    expect($verifier->supports($ssha))->toBeFalse()
        ->and($verifier->verify('secret', $ssha))->toBeFalse()
        ->and($verifier->supports($md5))->toBeFalse()
        ->and($verifier->verify('secret', $md5))->toBeFalse()
        ->and($verifier->supports($sha1))->toBeFalse()
        ->and($verifier->verify('secret', $sha1))->toBeFalse();
});

it('the registry refuses a format no registered verifier supports', function (): void {
    $registry = new HashVerifierRegistry(new NativePasswordVerifier(PASSWORD_BCRYPT, ['cost' => 12]));

    $foreign = 'scrypt$'.base64_encode('whatever');

    expect($registry->supports($foreign))->toBeFalse()
        ->and($registry->verify('whatever', $foreign))->toBeFalse();
});

it('the registry delegates to the first verifier that supports the format', function (): void {
    $registry = new HashVerifierRegistry(new NativePasswordVerifier(PASSWORD_BCRYPT, ['cost' => 12]));

    $bcrypt = password_hash('pw', PASSWORD_BCRYPT);

    expect($registry->supports($bcrypt))->toBeTrue()
        ->and($registry->verify('pw', $bcrypt))->toBeTrue()
        ->and($registry->verify('nope', $bcrypt))->toBeFalse();
});

it('binds a deny-by-default registry to the HashVerifier contract', function (): void {
    expect(app(HashVerifier::class))->toBeInstanceOf(HashVerifierRegistry::class);
});
