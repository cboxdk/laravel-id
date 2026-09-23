<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\GrantType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\ClientBlueprint;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * Promote an app from one environment to another.
 *
 * Client ids are minted per environment, so there was no way to say "this app, in
 * production": the only route was to retype every setting by hand and hope. A blueprint
 * is the app's configuration without its identity or its credentials.
 */
function blueprintSource(): RegisteredClient
{
    return app(ClientRegistry::class)->register(new NewClient(
        name: 'Cortex',
        redirectUris: ['https://staging.cortex.test/cb', 'https://staging.cortex.test/alt'],
        grantTypes: [GrantType::TokenExchange->value, 'authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'api.read'],
        firstParty: true,
        postLogoutRedirectUris: ['https://staging.cortex.test/bye'],
        accessTokenTtl: 600,
        tokenEndpointAuthMethod: TokenEndpointAuthMethod::ClientSecretPost,
        manifestUrl: 'https://staging.cortex.test/manifest.json',
    ));
}

it('exports a deterministic, versioned document', function (): void {
    $source = blueprintSource();

    $json = app(ClientRegistry::class)->blueprint($source->client)->toJson();

    // The exact bytes, so a key rename, a reordering or an unsorted list is a failing
    // test rather than a noisy diff in somebody's repository.
    expect($json)->toBe(<<<'JSON'
        {
            "kind": "cbox-id.client-blueprint",
            "version": 1,
            "name": "Cortex",
            "client_type": "confidential",
            "token_endpoint_auth_method": "client_secret_post",
            "grant_types": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:token-exchange"
            ],
            "redirect_uris": [
                "https://staging.cortex.test/alt",
                "https://staging.cortex.test/cb"
            ],
            "post_logout_redirect_uris": [
                "https://staging.cortex.test/bye"
            ],
            "scopes": [
                "api.read",
                "openid",
                "profile"
            ],
            "first_party": true,
            "manifest_url": "https://staging.cortex.test/manifest.json",
            "access_token_ttl": 600
        }

        JSON);

    // Same app, same bytes.
    expect(app(ClientRegistry::class)->blueprint(Client::query()->findOrFail($source->client->id))->toJson())->toBe($json);
});

it('carries no identity and no credential', function (): void {
    $source = blueprintSource();
    $json = app(ClientRegistry::class)->blueprint($source->client)->toJson();

    expect($json)->not->toContain($source->client->client_id)
        ->and($json)->not->toContain((string) $source->secret)
        ->and($json)->not->toContain((string) $source->client->secret_hash)
        ->and($json)->not->toContain($source->client->environment_id);
});

it('imports into another environment as a new client, with its own id and secret', function (): void {
    $source = blueprintSource();
    $json = app(ClientRegistry::class)->blueprint($source->client)->toJson();

    $imported = $this->runAsEnvironment('env_prod', function () use ($json): RegisteredClient {
        $blueprint = ClientBlueprint::fromJson($json)
            ->withRedirectUris(['https://cortex.test/cb'])
            ->withPostLogoutRedirectUris(['https://cortex.test/bye'])
            ->withManifestUrl('https://cortex.test/manifest.json');

        return app(ClientRegistry::class)->import($blueprint);
    });

    expect($imported->client->environment_id)->toBe('env_prod')
        ->and($imported->client->client_id)->not->toBe($source->client->client_id)
        ->and($imported->secret)->toBeString()->toStartWith('csec_')
        ->and($imported->secret)->not->toBe($source->secret)
        ->and($imported->client->redirect_uris)->toBe(['https://cortex.test/cb'])
        ->and($imported->client->grant_types)->toBe(['authorization_code', 'refresh_token', GrantType::TokenExchange->value])
        ->and($imported->client->scopes)->toBe(['api.read', 'openid', 'profile'])
        ->and($imported->client->first_party)->toBeTrue()
        ->and($imported->client->access_token_ttl)->toBe(600)
        ->and($imported->client->token_endpoint_auth_method)->toBe(TokenEndpointAuthMethod::ClientSecretPost)
        ->and($imported->client->manifest_url)->toBe('https://cortex.test/manifest.json');

    // The environments stay apart: each secret authenticates only its own client.
    $this->runAsEnvironment('env_prod', function () use ($imported, $source): void {
        $registry = app(ClientRegistry::class);

        expect($registry->verifySecret($imported->client, (string) $imported->secret))->toBeTrue()
            ->and($registry->verifySecret($imported->client, (string) $source->secret))->toBeFalse()
            ->and($registry->byClientId($source->client->client_id))->toBeNull();
    });
});

it('audits an import as a creation from a blueprint', function (): void {
    $blueprint = app(ClientRegistry::class)->blueprint(blueprintSource()->client);
    $audit = $this->fakeAudit();

    app(ClientRegistry::class)->import($blueprint);

    $audit->assertRecorded('app.created');
    expect($audit->recorded[0]->context['source'])->toBe('blueprint');
});

it('needs the target environment\'s keys to import a private_key_jwt client', function (): void {
    $jwks = ['keys' => [['kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB', 'kid' => 'k1']]];
    $blueprint = new ClientBlueprint(
        name: 'Signer',
        tokenEndpointAuthMethod: TokenEndpointAuthMethod::PrivateKeyJwt,
        grantTypes: ['client_credentials'],
    );

    expect(fn () => app(ClientRegistry::class)->import($blueprint))
        ->toThrow(InvalidClientMetadata::class, 'private_key_jwt');

    $imported = app(ClientRegistry::class)->import($blueprint, jwks: $jwks);

    expect($imported->secret)->toBeNull()
        ->and($imported->client->jwks)->toBe($jwks);
});

it('imports under the owning organization it is given', function (): void {
    $org = $this->makeOrganization();

    $imported = app(ClientRegistry::class)->import(new ClientBlueprint(name: 'Tenant app', grantTypes: ['client_credentials']), $org->id);

    expect($imported->client->organization_id)->toBe($org->id);
});

it('refuses a document it cannot honour, and says why', function (array $patch, string $reason): void {
    $document = array_merge((new ClientBlueprint(name: 'App', grantTypes: ['client_credentials']))->toArray(), $patch);

    expect(fn () => ClientBlueprint::fromArray($document))->toThrow(InvalidClientMetadata::class, $reason);
})->with([
    'a secret smuggled in' => [['client_secret' => 'csec_x'], 'unknown key(s): client_secret'],
    'a client id smuggled in' => [['client_id' => 'cid_x'], 'unknown key(s): client_id'],
    'a future version' => [['version' => 2], 'unsupported version'],
    'some other document' => [['kind' => 'something-else'], '"kind" must be'],
    'no name' => [['name' => '  '], '"name" must be a non-empty string'],
    'an unknown client type' => [['client_type' => 'trusted'], '"client_type" must be'],
    'an unknown auth method' => [['token_endpoint_auth_method' => 'tls_client_auth'], 'not a supported method'],
    'an unknown grant' => [['grant_types' => ['password']], 'grant_type not supported: password'],
    'token exchange on a public client' => [['client_type' => 'public', 'grant_types' => [GrantType::TokenExchange->value]], 'requires a confidential client'],
    'a method that contradicts the type' => [['client_type' => 'public', 'token_endpoint_auth_method' => 'client_secret_basic'], 'does not match a public client'],
    'a redirect with a fragment' => [['redirect_uris' => ['https://app.test/cb#x']], 'must not contain a fragment'],
    'a script redirect' => [['redirect_uris' => ['javascript:alert(1)']], 'reverse-domain name'],
    'a code grant with nowhere to return' => [['grant_types' => ['authorization_code']], 'redirect_uris is required'],
    'a TTL out of bounds' => [['access_token_ttl' => 5], 'access_token_ttl must be between'],
    'a TTL as a string' => [['access_token_ttl' => '600'], '"access_token_ttl" must be an integer'],
    'first_party as a string' => [['first_party' => 'yes'], '"first_party" must be a boolean'],
    'scopes as a string' => [['scopes' => 'openid profile'], '"scopes" must be a list of strings'],
    'a scope with a space' => [['scopes' => ['openid profile']], 'without whitespace'],
    'a manifest that is no URL' => [['manifest_url' => 'not a url'], '"manifest_url" must be an absolute URL'],
]);

it('refuses JSON that is not a blueprint object', function (string $json): void {
    expect(fn () => ClientBlueprint::fromJson($json))->toThrow(InvalidClientMetadata::class, 'Invalid client blueprint');
})->with(['not json', '[]', '"a string"']);

it('round-trips through its own document unchanged', function (): void {
    $blueprint = app(ClientRegistry::class)->blueprint(blueprintSource()->client);

    expect(ClientBlueprint::fromJson($blueprint->toJson())->toArray())->toBe($blueprint->toArray());
});

it('reads a public client back as public', function (): void {
    $public = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code']);

    expect(app(ClientRegistry::class)->blueprint($public->client)->toArray()['client_type'])->toBe('public');
});
