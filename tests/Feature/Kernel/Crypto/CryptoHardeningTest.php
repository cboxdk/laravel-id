<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('stamps access tokens with the at+jwt type header (RFC 9068)', function (): void {
    $registered = $this->makeClient(['api.read']);
    $token = app(TokenIssuer::class)->issueClientCredentials($registered->client);

    // Decode the JWT header (first segment) and check typ.
    $header = json_decode(Base64Url::decode(explode('.', $token->token)[0]), true);

    expect($header['typ'] ?? null)->toBe('at+jwt')
        ->and($header['alg'] ?? null)->toBe('RS256');
});

it('rotates the active signing key via the artisan command', function (): void {
    // Mint an initial active key.
    app(KeyManager::class)->activeSigningKey();
    $before = SigningKey::query()->where('status', KeyStatus::Active->value)->value('kid');

    $this->artisan('cbox-id:keys:rotate', ['--alg' => 'RS256'])->assertSuccessful();

    $after = SigningKey::query()->where('status', KeyStatus::Active->value)->value('kid');

    expect($after)->not->toBe($before) // a fresh active key
        ->and(SigningKey::query()->where('kid', $before)->value('status'))->toBe(KeyStatus::Rotating); // old kept for overlap
});

it('retires rotating keys older than the overlap window', function (): void {
    app(KeyManager::class)->activeSigningKey();
    $this->artisan('cbox-id:keys:rotate', ['--alg' => 'RS256'])->assertSuccessful(); // key A -> Rotating
    $agedKid = SigningKey::query()->where('status', KeyStatus::Rotating->value)->value('kid');

    // Two hours pass, then rotate again and retire anything rotating for > 1h.
    $this->travel(2)->hours();
    $this->artisan('cbox-id:keys:rotate', ['--alg' => 'RS256', '--retire-after' => '1'])->assertSuccessful();

    // The old key A (rotating for 2h) is retired; the just-rotated key stays.
    expect(SigningKey::query()->where('kid', $agedKid)->value('status'))->toBe(KeyStatus::Retired)
        ->and(SigningKey::query()->where('status', KeyStatus::Rotating->value)->count())->toBe(1);
});
