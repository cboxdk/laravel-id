<?php

declare(strict_types=1);

use Cbox\Id\FeatureFlags\Contracts\FeatureFlags;
use Cbox\Id\FeatureFlags\ValueObjects\FeatureFlagChanges;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Cbox\Id\Tests\Fixtures\Actions\FeatureFlagsClaimAction;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

const FLAG_VERIFIER = 'a-sufficiently-long-code-verifier-for-feature-flags';

/**
 * The `feature_flags` claim: on the access token, the ID token and UserInfo, only when the
 * grant holds the `feature_flags` scope — and then always, as a possibly-empty list.
 *
 * @param  list<string>  $scopes
 */
function redeemWithFlags(object $test, RegisteredClient $registered, array $scopes, string $userId, ?string $organizationId): TestResponse
{
    $code = app(AuthorizationCodes::class)->issue(
        $registered->client->client_id,
        $userId,
        $organizationId,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', FLAG_VERIFIER, true)),
        'S256',
        null,
        1_700_000_000,
        ['pwd'],
    );

    return $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => FLAG_VERIFIER,
    ])->assertOk();
}

/** @return array<string, mixed> */
function verified(string $jwt): array
{
    return app(TokenSigner::class)->verify($jwt, [SigningAlg::RS256])->all();
}

beforeEach(function (): void {
    $this->acme = $this->makeOrganization('Acme');
    $this->user = $this->makeUser('ada@example.com');

    $this->createFeatureFlag('everyone', defaultValue: true);
    $this->createFeatureFlag('acme-beta', FlagTargeting::organizations([$this->acme->id]));
    $this->createFeatureFlag('nobody');
});

it('carries the flags that are on in the access token, ID token and UserInfo when the scope is granted', function (): void {
    $response = redeemWithFlags($this, $this->makeClient(['openid', 'feature_flags'], grantTypes: ['authorization_code']), ['openid', 'feature_flags'], $this->user->id, $this->acme->id);

    expect(verified($response->json('access_token'))['feature_flags'])->toBe(['acme-beta', 'everyone'])
        ->and(verified($response->json('id_token'))['feature_flags'])->toBe(['acme-beta', 'everyone']);

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$response->json('access_token')])
        ->assertOk()
        ->assertJsonPath('feature_flags', ['acme-beta', 'everyone']);
});

it('leaves every token and UserInfo without the claim when the scope was not granted', function (): void {
    $response = redeemWithFlags($this, $this->makeClient(['openid'], grantTypes: ['authorization_code']), ['openid'], $this->user->id, $this->acme->id);

    expect(verified($response->json('access_token')))->not->toHaveKey('feature_flags')
        ->and(verified($response->json('id_token')))->not->toHaveKey('feature_flags');

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$response->json('access_token')])
        ->assertOk()
        ->assertJsonMissingPath('feature_flags');
});

it('carries an empty list rather than nothing when the scope is granted and nothing is on', function (): void {
    app(FeatureFlags::class)->update(
        app(FeatureFlags::class)->findByKey('everyone')?->id ?? '',
        FeatureFlagChanges::make()->withEnabled(false),
    );

    $response = redeemWithFlags($this, $this->makeClient(['openid', 'feature_flags'], grantTypes: ['authorization_code']), ['openid', 'feature_flags'], $this->user->id, null);

    expect(verified($response->json('access_token'))['feature_flags'])->toBe([]);
});

it('reads UserInfo live, so a flag flipped after minting shows there first', function (): void {
    $response = redeemWithFlags($this, $this->makeClient(['openid', 'feature_flags'], grantTypes: ['authorization_code']), ['openid', 'feature_flags'], $this->user->id, $this->acme->id);

    app(FeatureFlags::class)->update(
        app(FeatureFlags::class)->findByKey('nobody')?->id ?? '',
        FeatureFlagChanges::make()->withTargeting(FlagTargeting::users([$this->user->id])),
    );

    // The token says what was true when it was minted …
    expect(verified($response->json('access_token'))['feature_flags'])->toBe(['acme-beta', 'everyone']);

    // … UserInfo says what is true now.
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$response->json('access_token')])
        ->assertJsonPath('feature_flags', ['acme-beta', 'everyone', 'nobody']);
});

it('evaluates a machine token for its organization alone', function (): void {
    $registered = $this->makeClient(['feature_flags'], grantTypes: ['client_credentials'], organizationId: $this->acme->id);

    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'feature_flags',
    ])->assertOk()->json('access_token');

    expect(verified($token)['feature_flags'])->toBe(['acme-beta', 'everyone']);
});

it('does not let a token hook rewrite the claim once the scope is granted, and leaves the name free without it', function (): void {
    config()->set('cbox-id.external_actions.hooks.token_minting', [FeatureFlagsClaimAction::class]);
    $client = $this->makeClient(['openid', 'feature_flags'])->client;

    $granted = verified(app(TokenIssuer::class)->issueForUser($client, $this->user->id, null, ['openid', 'feature_flags'])->token);
    $without = verified(app(TokenIssuer::class)->issueForUser($client, $this->user->id, null, ['openid'])->token);

    expect($granted['feature_flags'])->toBe(['everyone'])
        ->and($without['feature_flags'])->toBe(['forged-by-hook']);
});

it('advertises the scope and the claim in discovery', function (): void {
    $discovery = $this->getJson('/.well-known/openid-configuration')->assertOk();

    expect($discovery->json('scopes_supported'))->toContain('feature_flags')
        ->and($discovery->json('claims_supported'))->toContain('feature_flags');
});
