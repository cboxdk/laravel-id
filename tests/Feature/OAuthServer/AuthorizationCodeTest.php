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
