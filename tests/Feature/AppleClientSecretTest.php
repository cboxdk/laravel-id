<?php

declare(strict_types=1);

use Cbox\Id\Federation\AppleClientSecret;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Apple's client secret is minted, not pasted — so the thing to prove is that what we
 * mint is a real ES256 JWT that verifies against the key's public half, with the exact
 * claims Apple requires.
 */
function appleKeypair(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
    openssl_pkey_export($key, $private);
    $public = openssl_pkey_get_details($key)['key'];

    return [$private, $public];
}

it('mints a client secret that verifies against the signing key', function (): void {
    [$private, $public] = appleKeypair();

    $secret = app(AppleClientSecret::class)->mint('conn-1', 'TEAM123456', 'KEY1234567', $private, 'com.acme.service');

    // Verified with a real signature check, not by parsing our own output — a token we
    // only ever decode ourselves proves nothing about whether Apple would accept it.
    $claims = (array) JWT::decode($secret, new Key($public, 'ES256'));

    expect($claims['iss'])->toBe('TEAM123456')
        ->and($claims['sub'])->toBe('com.acme.service')
        ->and($claims['aud'])->toBe('https://appleid.apple.com')
        ->and($claims['exp'] - $claims['iat'])->toBe(3600);
});

it('names the key id in the header, which is how Apple finds the key', function (): void {
    [$private] = appleKeypair();

    $secret = app(AppleClientSecret::class)->mint('conn-1', 'TEAM123456', 'KEY1234567', $private, 'com.acme.service');
    $header = json_decode(base64_decode(strtr(explode('.', $secret)[0], '-_', '+/')) ?: '{}', true);

    expect($header['kid'] ?? null)->toBe('KEY1234567')
        ->and($header['alg'] ?? null)->toBe('ES256');
});

it('reuses a minted secret rather than signing on every request', function (): void {
    [$private] = appleKeypair();

    $first = app(AppleClientSecret::class)->mint('conn-1', 'TEAM123456', 'KEY1234567', $private, 'com.acme.service');
    $second = app(AppleClientSecret::class)->mint('conn-1', 'TEAM123456', 'KEY1234567', $private, 'com.acme.service');

    expect($second)->toBe($first);
});

it('mints afresh when the key material changes, rather than serving the old one', function (): void {
    [$first] = appleKeypair();
    [$second] = appleKeypair();

    $a = app(AppleClientSecret::class)->mint('conn-1', 'TEAM123456', 'KEY1234567', $first, 'com.acme.service');
    $b = app(AppleClientSecret::class)->mint('conn-1', 'TEAM123456', 'KEY1234567', $second, 'com.acme.service');

    // Rotating a key or correcting a mistyped team id has to take effect now, not after
    // the cache expires — otherwise the fix appears not to work and gets "fixed" again.
    expect($b)->not->toBe($a);
});

it('says what is usually wrong when the key will not load', function (): void {
    expect(fn () => app(AppleClientSecret::class)->mint('conn-1', 'TEAM123456', 'KEY1234567', 'not a key', 'com.acme.service'))
        ->toThrow(InvalidAssertion::class, 'pasted whole');
});
