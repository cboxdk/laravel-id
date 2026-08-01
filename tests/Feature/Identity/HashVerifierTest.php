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

/**
 * Hashes this process did NOT create — which is the only kind that matters here.
 *
 * `password_hash()` on PHP 8 emits `$2y$` and nothing else, so a test that hashes and
 * then verifies can only ever exercise `$2y$`. The docblock on NativePasswordVerifier
 * promises `$2a$` and `$2b$` too, and that promise is the whole point of the class:
 * it is what lets a customer move off another provider without every one of their users
 * being forced to reset a password. It was proven by comment only.
 *
 * The three `$2a$` entries are the canonical crypt_blowfish/openwall vectors, chosen
 * because they are genuinely foreign to this codebase. `U*U*U` in particular is the one
 * that separates a correct bcrypt from the historically broken ones.
 *
 * `$2b$` is a `$2y$` hash re-prefixed: the two differ only in the prefix, so re-labelling
 * produces exactly what a `$2b$`-emitting exporter would have sent — the point being that
 * the verifier must not reject a family it claims to accept on the strength of two bytes.
 *
 * The argon2 hashes were generated out-of-process, so their encoded parameters are fixed
 * strings rather than whatever this machine's config happens to produce.
 */
it('verifies foreign bcrypt and argon2 hashes it did not produce', function (string $password, string $hash): void {
    $verifier = new NativePasswordVerifier(PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);

    expect($verifier->supports($hash))->toBeTrue("format not recognized: {$hash}")
        ->and($verifier->verify($password, $hash))->toBeTrue("correct password rejected: {$hash}")
        ->and($verifier->verify($password.'x', $hash))->toBeFalse("wrong password accepted: {$hash}");
})->with([
    'bcrypt $2a$ — openwall U*U' => ['U*U', '$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'],
    'bcrypt $2a$ — openwall U*U*' => ['U*U*', '$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK'],
    'bcrypt $2a$ — openwall U*U*U' => ['U*U*U', '$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a'],
    'bcrypt $2b$' => ['correct-horse-battery-staple', '$2b$05$BF4hcncPNxRibgDOWjaJd.1fsgdwFPySkMCmZyH4oIQ4l0pnMck9y'],
    'bcrypt $2y$' => ['correct-horse-battery-staple', '$2y$05$BF4hcncPNxRibgDOWjaJd.1fsgdwFPySkMCmZyH4oIQ4l0pnMck9y'],
    'argon2id' => ['correct-horse-battery-staple', '$argon2id$v=19$m=65536,t=4,p=1$DVLDImQwpbYZLqA8gKZGfg$CwOXpuEFXSfc7zqgsIr8K7v2PFT/sF0gczGJIhgkXQQ'],
    'argon2i' => ['correct-horse-battery-staple', '$argon2i$v=19$m=65536,t=4,p=1$uVkPvSeUxx1jILPKXA74iw$ErYCiTXxDprUfXdJ4PlsK6zW6WmDRqAKkzBuBIcisa8'],
]);

/**
 * A weak bcrypt cost is still a valid bcrypt hash: it must verify, and it must be
 * flagged for upgrade on the way past. An importer that only did the first half would
 * leave a customer's cost-05 hashes at cost 05 forever.
 */
it('upgrades an imported hash to the platform standard on next sign-in', function (): void {
    $verifier = new NativePasswordVerifier(PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);

    expect($verifier->needsRehash('$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW'))->toBeTrue()
        ->and($verifier->needsRehash('$argon2id$v=19$m=65536,t=4,p=1$DVLDImQwpbYZLqA8gKZGfg$CwOXpuEFXSfc7zqgsIr8K7v2PFT/sF0gczGJIhgkXQQ'))->toBeFalse();
});
