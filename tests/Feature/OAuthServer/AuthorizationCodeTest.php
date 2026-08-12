<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @return array{verifier: string, challenge: string}
 */
function pkcePair(string $verifier = 'a-sufficiently-long-code-verifier-1234567890'): array
{
    return [
        'verifier' => $verifier,
        'challenge' => Base64Url::encode(hash('sha256', $verifier, true)),
    ];
}

it('exchanges a code with a valid PKCE verifier', function (): void {
    ['verifier' => $verifier, 'challenge' => $challenge] = pkcePair();
    $codes = app(AuthorizationCodes::class);

    $code = $codes->issue('cid_1', 'user_1', 'org_a', 'https://app.test/cb', ['openid', 'profile'], $challenge);
    $grant = $codes->exchange('cid_1', $code, 'https://app.test/cb', $verifier);

    expect($grant->userId)->toBe('user_1')
        ->and($grant->organizationId)->toBe('org_a')
        ->and($grant->scopes)->toBe(['openid', 'profile']);
});

it('rejects a wrong PKCE verifier', function (): void {
    ['challenge' => $challenge] = pkcePair();
    $codes = app(AuthorizationCodes::class);

    $code = $codes->issue('cid_1', 'user_1', null, 'https://app.test/cb', ['openid'], $challenge);

    $codes->exchange('cid_1', $code, 'https://app.test/cb', 'the-wrong-verifier');
})->throws(InvalidGrant::class);

it('rejects reuse of a consumed code', function (): void {
    ['verifier' => $verifier, 'challenge' => $challenge] = pkcePair();
    $codes = app(AuthorizationCodes::class);

    $code = $codes->issue('cid_1', 'user_1', null, 'https://app.test/cb', ['openid'], $challenge);
    $codes->exchange('cid_1', $code, 'https://app.test/cb', $verifier);

    $codes->exchange('cid_1', $code, 'https://app.test/cb', $verifier);
})->throws(InvalidGrant::class);

it('rejects a redirect_uri mismatch', function (): void {
    ['verifier' => $verifier, 'challenge' => $challenge] = pkcePair();
    $codes = app(AuthorizationCodes::class);

    $code = $codes->issue('cid_1', 'user_1', null, 'https://app.test/cb', ['openid'], $challenge);

    $codes->exchange('cid_1', $code, 'https://attacker.test/cb', $verifier);
})->throws(InvalidGrant::class);

it('rejects a client mismatch', function (): void {
    ['verifier' => $verifier, 'challenge' => $challenge] = pkcePair();
    $codes = app(AuthorizationCodes::class);

    $code = $codes->issue('cid_1', 'user_1', null, 'https://app.test/cb', ['openid'], $challenge);

    $codes->exchange('cid_other', $code, 'https://app.test/cb', $verifier);
})->throws(InvalidGrant::class);

it('rejects an unknown code', function (): void {
    app(AuthorizationCodes::class)->exchange('cid_1', 'ac_does_not_exist', 'https://app.test/cb', 'v');
})->throws(InvalidGrant::class);

/**
 * RFC 7636's SHAPES ARE THE SECURITY PROPERTY, not decoration.
 *
 * The verifier's 43–128 unreserved characters are what make it hold the entropy the
 * challenge commits to; a short one is a guessable one. And `plain` was accepted at issue
 * time and then unredeemable, because redemption always computes S256 — the right
 * direction, at the wrong moment. The host got a working code and the user got a broken
 * sign-in, with the error surfacing at the exchange where nothing says which end was
 * wrong.
 */
it('refuses a code_challenge_method other than S256, at issue time', function (): void {
    ['challenge' => $challenge] = pkcePair();

    expect(fn () => app(AuthorizationCodes::class)->issue(
        'cid_1', 'user_1', null, 'https://app.test/cb', ['openid'], $challenge, 'plain',
    ))->toThrow(InvalidGrant::class);
});

it('refuses a challenge that is not a base64url S256 digest', function (): void {
    expect(fn () => app(AuthorizationCodes::class)->issue(
        'cid_1', 'user_1', null, 'https://app.test/cb', ['openid'], 'not-a-digest',
    ))->toThrow(InvalidGrant::class);
});

it('refuses a verifier outside RFC 7636 length and alphabet', function (): void {
    $codes = app(AuthorizationCodes::class);

    // Too short — 42 characters, one under the floor.
    $short = str_repeat('a', 42);
    $code = $codes->issue('cid_1', 'user_1', null, 'https://app.test/cb', ['openid'],
        Base64Url::encode(hash('sha256', $short, true)));

    expect(fn () => $codes->exchange('cid_1', $code, 'https://app.test/cb', $short))
        ->toThrow(InvalidGrant::class);

    // In range, but carrying a character the grammar does not admit.
    $illegal = str_repeat('a', 40).'/+=';
    $second = $codes->issue('cid_1', 'user_1', null, 'https://app.test/cb', ['openid'],
        Base64Url::encode(hash('sha256', $illegal, true)));

    expect(fn () => $codes->exchange('cid_1', $second, 'https://app.test/cb', $illegal))
        ->toThrow(InvalidGrant::class);
});
