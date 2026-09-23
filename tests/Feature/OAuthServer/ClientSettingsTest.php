<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\GrantType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\ValueObjects\ClientBlueprint;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/**
 * What the registry accepts as a client's settings, on register and on update — the one
 * door every console uses, so a console cannot offer what the token endpoint will refuse.
 */
function settingsRegistry(): ClientRegistry
{
    return app(ClientRegistry::class);
}

function exchangeAs(object $test, string $clientId, string $secret, string $subjectToken): TestResponse
{
    return $test->postJson('/oauth/token', [
        'grant_type' => GrantType::TokenExchange->value,
        'client_id' => $clientId,
        'client_secret' => $secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
    ]);
}

it('enables and disables token exchange on an existing client through update', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read'], grantTypes: ['client_credentials']);
    $client = $registered->client;
    $secret = (string) $registered->secret;
    $subject = app(TokenIssuer::class)->issueForUser($client, 'alice', $org->id, ['api.read'])->token;

    exchangeAs($this, $client->client_id, $secret, $subject)->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');

    settingsRegistry()->update($client, settingsRegistry()->blueprint($client)
        ->withGrantTypes(['client_credentials', GrantType::TokenExchange->value]));

    exchangeAs($this, $client->client_id, $secret, $subject)->assertOk();

    settingsRegistry()->update($client, settingsRegistry()->blueprint($client)->withGrantTypes(['client_credentials']));

    exchangeAs($this, $client->client_id, $secret, $subject)->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
});

it('refuses token exchange for a public client, on register and on update', function (): void {
    expect(fn () => settingsRegistry()->register(new NewClient(
        name: 'SPA',
        type: ClientType::Public,
        redirectUris: ['https://app.test/cb'],
        grantTypes: ['authorization_code', GrantType::TokenExchange->value],
    )))->toThrow(InvalidClientMetadata::class, 'requires a confidential client');

    $public = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code']);

    expect(fn () => settingsRegistry()->update($public->client, settingsRegistry()->blueprint($public->client)
        ->withGrantTypes(['authorization_code', GrantType::TokenExchange->value])))
        ->toThrow(InvalidClientMetadata::class, 'requires a confidential client');

    expect($public->client->fresh()?->grant_types)->toBe(['authorization_code']);
});

it('refuses a grant the token endpoint does not implement', function (): void {
    expect(fn () => settingsRegistry()->register(new NewClient(name: 'Old', grantTypes: ['password'])))
        ->toThrow(InvalidClientMetadata::class, 'grant_type not supported: password');
});

it('refuses token exchange for a public client through dynamic registration too', function (): void {
    config()->set('cbox-id.oauth.dynamic_registration.mode', 'open');

    $this->postJson('/oauth/register', [
        'client_name' => 'Public exchanger',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code', GrantType::TokenExchange->value],
        'redirect_uris' => ['https://app.test/cb'],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_client_metadata');
});

it('sets, changes and clears a client TTL through the registry', function (): void {
    $registered = settingsRegistry()->register(new NewClient(name: 'kubectl', accessTokenTtl: 300));
    $client = $registered->client;

    expect($client->access_token_ttl)->toBe(300);

    settingsRegistry()->update($client, settingsRegistry()->blueprint($client)->withAccessTokenTtl(600));
    expect($client->fresh()?->access_token_ttl)->toBe(600);

    settingsRegistry()->update($client, settingsRegistry()->blueprint($client)->withAccessTokenTtl(null));
    expect($client->fresh()?->access_token_ttl)->toBeNull();
});

it('refuses a TTL outside the configured bounds', function (int $ttl): void {
    config()->set('cbox-id.oauth.max_access_token_ttl', 3600);

    expect(fn () => settingsRegistry()->register(new NewClient(name: 'x', accessTokenTtl: $ttl)))
        ->toThrow(InvalidClientMetadata::class, 'access_token_ttl must be between 60 and 3600 seconds');

    $client = $this->makeClient()->client;

    expect(fn () => settingsRegistry()->update($client, settingsRegistry()->blueprint($client)->withAccessTokenTtl($ttl)))
        ->toThrow(InvalidClientMetadata::class, 'access_token_ttl must be between 60 and 3600 seconds');
})->with([0, 59, 3601]);

it('refuses to change the client type or authentication method through update', function (): void {
    $client = $this->makeClient()->client;
    $blueprint = settingsRegistry()->blueprint($client);

    $asPublic = new ClientBlueprint(
        name: $blueprint->name,
        type: ClientType::Public,
        grantTypes: ['authorization_code'],
        redirectUris: ['https://app.test/cb'],
    );

    expect(fn () => settingsRegistry()->update($client, $asPublic))
        ->toThrow(InvalidClientMetadata::class, 'client_type cannot be changed');

    $asPost = new ClientBlueprint(
        name: $blueprint->name,
        tokenEndpointAuthMethod: TokenEndpointAuthMethod::ClientSecretPost,
        grantTypes: $blueprint->grantTypes,
    );

    expect(fn () => settingsRegistry()->update($client, $asPost))
        ->toThrow(InvalidClientMetadata::class, 'token_endpoint_auth_method cannot be changed');
});

it('refuses an authentication method that contradicts the client', function (): void {
    expect(fn () => settingsRegistry()->register(new NewClient(
        name: 'x',
        type: ClientType::Public,
        grantTypes: ['authorization_code'],
        tokenEndpointAuthMethod: TokenEndpointAuthMethod::ClientSecretBasic,
    )))->toThrow(InvalidClientMetadata::class, 'does not match a public client');

    expect(fn () => settingsRegistry()->register(new NewClient(
        name: 'x',
        tokenEndpointAuthMethod: TokenEndpointAuthMethod::PrivateKeyJwt,
    )))->toThrow(InvalidClientMetadata::class, 'private_key_jwt');
});

it('persists the manifest URL and authentication method given at registration', function (): void {
    $client = settingsRegistry()->register(new NewClient(
        name: 'Cortex',
        tokenEndpointAuthMethod: TokenEndpointAuthMethod::ClientSecretPost,
        manifestUrl: 'https://cortex.test/.well-known/cbox-id-manifest.json',
    ))->client->fresh();

    expect($client?->token_endpoint_auth_method)->toBe(TokenEndpointAuthMethod::ClientSecretPost)
        ->and($client?->manifest_url)->toBe('https://cortex.test/.well-known/cbox-id-manifest.json');
});
