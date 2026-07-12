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

it('injects default iat and a unique jti when the caller omits them', function (): void {
    $signer = app(TokenSigner::class);

    $one = $signer->verify($signer->sign(['sub' => 'user_1']), [SigningAlg::RS256]);
    $two = $signer->verify($signer->sign(['sub' => 'user_1']), [SigningAlg::RS256]);

    expect($one->get('iat'))->toBeInt()
        ->and($one->get('jti'))->toBeString()
        ->and($one->get('jti'))->not->toBe($two->get('jti')); // unique per token
});

it('does not override caller-supplied iat and jti', function (): void {
    $signer = app(TokenSigner::class);

    $claims = $signer->verify(
        $signer->sign(['sub' => 'user_1', 'iat' => 1000, 'jti' => 'fixed-id']),
        [SigningAlg::RS256],
    );

    expect($claims->get('iat'))->toBe(1000)
        ->and($claims->get('jti'))->toBe('fixed-id');
});

it('rejects an empty allow-list', function (): void {
    $signer = app(TokenSigner::class);
    $jwt = $signer->sign(['sub' => 'user_1']);

    expect(fn () => $signer->verify($jwt, []))->toThrow(InvalidToken::class);
});
