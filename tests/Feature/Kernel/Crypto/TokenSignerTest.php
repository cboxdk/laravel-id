<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('signs and verifies a token round-trip', function (): void {
    $signer = app(TokenSigner::class);

    $jwt = $signer->sign(['sub' => 'user_1', 'scope' => 'read']);
    $claims = $signer->verify($jwt, [SigningAlg::RS256]);

    expect($claims->subject())->toBe('user_1')
        ->and($claims->get('scope'))->toBe('read');
});

it('rejects a token whose algorithm is not in the allow-list', function (): void {
    $signer = app(TokenSigner::class);
    $jwt = $signer->sign(['sub' => 'user_1'], SigningAlg::RS256);

    // Attacker-controlled or simply disallowed algorithm: no key is offered for it.
    expect(fn () => $signer->verify($jwt, [SigningAlg::ES256]))->toThrow(InvalidToken::class);
});

it('rejects a token with a forged signature', function (): void {
    $signer = app(TokenSigner::class);
    $jwt = $signer->sign(['sub' => 'user_1']);

    $parts = explode('.', $jwt);
    $parts[2] = Base64Url::encode(str_repeat("\0", 32)); // bogus signature
    $forged = implode('.', $parts);

    expect(fn () => $signer->verify($forged, [SigningAlg::RS256]))->toThrow(InvalidToken::class);
});

it('rejects a token whose payload was altered', function (): void {
    $signer = app(TokenSigner::class);
    $jwt = $signer->sign(['sub' => 'user_1', 'role' => 'member']);

    $parts = explode('.', $jwt);
    $parts[1] = Base64Url::encode((string) json_encode(['sub' => 'user_1', 'role' => 'admin']));
    $forged = implode('.', $parts);

    expect(fn () => $signer->verify($forged, [SigningAlg::RS256]))->toThrow(InvalidToken::class);
});

it('rejects an expired token', function (): void {
    $signer = app(TokenSigner::class);
    $jwt = $signer->sign(['sub' => 'user_1', 'exp' => time() - 60]);

    expect(fn () => $signer->verify($jwt, [SigningAlg::RS256]))->toThrow(InvalidToken::class);
});

it('rejects an empty allow-list', function (): void {
    $signer = app(TokenSigner::class);
    $jwt = $signer->sign(['sub' => 'user_1']);

    expect(fn () => $signer->verify($jwt, []))->toThrow(InvalidToken::class);
});
