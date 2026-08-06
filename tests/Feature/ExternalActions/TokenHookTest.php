<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Exceptions\ActionDenied;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\Tests\Fixtures\Actions\DenyAction;
use Cbox\Id\Tests\Fixtures\Actions\EnrichClaimAction;
use Cbox\Id\Tests\Fixtures\Actions\ReservedClaimAction;
use Cbox\Id\Tests\Fixtures\Actions\ThrowingAction;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function hookClaims(string $jwt): array
{
    return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
}

it('leaves issuance unchanged when no hook is registered', function (): void {
    $client = $this->makeClient(['openid'])->client;

    $payload = hookClaims(app(TokenIssuer::class)->issueForUser($client, 'alice', 'org_x', ['openid'])->token);

    expect($payload)->toHaveKeys(['iss', 'sub', 'scope'])
        ->and($payload)->not->toHaveKey('tenant_tier');
});

it('lets a TokenMinting hook enrich the token with a custom claim', function (): void {
    config()->set('cbox-id.external_actions.hooks.token_minting', [EnrichClaimAction::class]);
    $client = $this->makeClient(['openid'])->client;

    $payload = hookClaims(app(TokenIssuer::class)->issueForUser($client, 'alice', 'org_x', ['openid'])->token);

    expect($payload['tenant_tier'])->toBe('pro');
});

it('never lets a hook overwrite a reserved claim', function (): void {
    config()->set('cbox-id.external_actions.hooks.token_minting', [ReservedClaimAction::class]);
    $client = $this->makeClient(['openid'])->client;

    $payload = hookClaims(app(TokenIssuer::class)->issueForUser($client, 'alice', 'org_x', ['openid'])->token);

    // `sub` is protected; the non-reserved claim still lands.
    expect($payload['sub'])->toBe('alice')
        ->and($payload['tenant_tier'])->toBe('pro');
});

it('vetoes issuance when a hook denies, writing no token row', function (): void {
    config()->set('cbox-id.external_actions.hooks.token_minting', [DenyAction::class]);
    $client = $this->makeClient(['openid'])->client;

    expect(fn () => app(TokenIssuer::class)->issueForUser($client, 'alice', 'org_x', ['openid']))
        ->toThrow(ActionDenied::class);

    // The veto fires before the jti row is written — no orphaned token.
    expect(AccessToken::query()->count())->toBe(0);
});

it('maps a token-endpoint veto to access_denied', function (): void {
    config()->set('cbox-id.external_actions.hooks.token_minting', [DenyAction::class]);
    $registered = $this->makeClient(['openid']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertStatus(400)->assertJsonPath('error', 'access_denied');
});

it('fails closed when a hook throws (a control that fails open is not a control)', function (): void {
    config()->set('cbox-id.external_actions.hooks.token_minting', [ThrowingAction::class]);
    $client = $this->makeClient(['openid'])->client;

    expect(fn () => app(TokenIssuer::class)->issueForUser($client, 'alice', 'org_x', ['openid']))
        ->toThrow(ActionDenied::class);
});

it('fails open only when explicitly configured', function (): void {
    config()->set('cbox-id.external_actions.fail_open', true);
    config()->set('cbox-id.external_actions.hooks.token_minting', [ThrowingAction::class]);
    $client = $this->makeClient(['openid'])->client;

    $payload = hookClaims(app(TokenIssuer::class)->issueForUser($client, 'alice', 'org_x', ['openid'])->token);

    expect($payload['sub'])->toBe('alice'); // issued despite the throwing hook
});
