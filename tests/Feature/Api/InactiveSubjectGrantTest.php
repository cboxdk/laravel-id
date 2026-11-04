<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->subject = $this->makeUser();
    $this->registered = $this->makeClient(['openid', 'offline_access'], ClientType::Public, ['authorization_code', 'refresh_token']);
    $this->verifier = str_repeat('a', 43);
    $this->code = app(AuthorizationCodes::class)->issue(
        $this->registered->client->client_id, $this->subject->id, null, 'https://app.test/cb',
        ['openid', 'offline_access'], Base64Url::encode(hash('sha256', $this->verifier, true)),
    );
    $this->exchange = [
        'grant_type' => 'authorization_code', 'client_id' => $this->registered->client->client_id,
        'code' => $this->code, 'redirect_uri' => 'https://app.test/cb', 'code_verifier' => $this->verifier,
    ];
});

it('refuses a code issued before deactivation without minting any tokens', function (): void {
    app(Subjects::class)->deactivate($this->subject->id);
    $this->postJson('/oauth/token', $this->exchange)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(AccessToken::query()->count())->toBe(0)->and(RefreshToken::query()->count())->toBe(0);

    app(Subjects::class)->reactivate($this->subject->id);
    $this->postJson('/oauth/token', $this->exchange)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('checks live status even when an external status change did not run the grant revoker', function (): void {
    User::query()->whereKey($this->subject->id)->update(['status' => UserStatus::Disabled]);
    $this->postJson('/oauth/token', $this->exchange)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(AccessToken::query()->count())->toBe(0)->and(RefreshToken::query()->count())->toBe(0);
});

it('refuses refresh for disabled or deleted users without creating a successor', function (bool $deleted): void {
    $tokens = $this->postJson('/oauth/token', $this->exchange)->assertOk();
    if ($deleted) {
        User::query()->whereKey($this->subject->id)->delete();
    } else {
        User::query()->whereKey($this->subject->id)->update(['status' => UserStatus::Disabled]);
    }
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $this->registered->client->client_id,
        'refresh_token' => $tokens->json('refresh_token'),
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(AccessToken::query()->count())->toBe(1)->and(RefreshToken::query()->count())->toBe(1);
})->with([false, true]);

it('refuses direct issuance for an inactive subject across user token issuers', function (): void {
    app(Subjects::class)->deactivate($this->subject->id);
    expect(fn () => app(TokenIssuer::class)->issueForUser($this->registered->client, $this->subject->id, null, ['openid']))->toThrow(InvalidGrant::class);
    expect(fn () => app(RefreshTokens::class)->issue($this->registered->client, $this->subject->id, null, ['openid']))->toThrow(InvalidGrant::class);
});

it('still exchanges and refreshes an active user grant', function (): void {
    $tokens = $this->postJson('/oauth/token', $this->exchange)->assertOk()->assertJsonStructure(['access_token', 'id_token', 'refresh_token']);
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token', 'client_id' => $this->registered->client->client_id,
        'refresh_token' => $tokens->json('refresh_token'),
    ])->assertOk()->assertJsonStructure(['access_token', 'id_token', 'refresh_token']);
});
