<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Testing;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\Contracts\AuthorizationClients;
use Cbox\Id\OAuthServer\Contracts\ClientAssertion;
use Cbox\Id\OAuthServer\Contracts\ClientIdMetadataDocuments;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\MetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Contracts\ServiceAccounts;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\Api;
use Cbox\Id\OAuthServer\ValueObjects\ApiScopeDefinition;
use Cbox\Id\OAuthServer\ValueObjects\NewApi;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;

trait InteractsWithOAuth
{
    /**
     * @param  list<string>  $scopes
     */
    protected function makeServiceAccount(string $organizationId, array $scopes = ['api.read'], string $name = 'CI bot'): RegisteredClient
    {
        return app(ServiceAccounts::class)->create($organizationId, $name, $scopes);
    }

    /**
     * Register a test client.
     *
     * `$grantTypes` is explicit because the token endpoint enforces the registered set:
     * a client may only use the grants it declared. Declaring them here keeps a test's
     * fixture honest about which flows it actually exercises.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $grantTypes
     */
    protected function makeClient(
        array $scopes = ['api.read'],
        ClientType $type = ClientType::Confidential,
        array $grantTypes = ['client_credentials'],
        ?int $accessTokenTtl = null,
        ?string $organizationId = null,
    ): RegisteredClient {
        return app(ClientRegistry::class)->register(
            new NewClient(
                'Test client',
                $type,
                redirectUris: ['https://app.test/cb'],
                grantTypes: $grantTypes,
                scopes: $scopes,
                organizationId: $organizationId,
                accessTokenTtl: $accessTokenTtl,
            ),
        );
    }

    /**
     * Register an API (resource server) in the current environment.
     *
     * Scopes are given as `key => tenantRequestable`, or as a bare key for a
     * tenant-requestable one: `['tax:read', 'tax:assess' => false]`.
     *
     * @param  array<int|string, string|bool>  $scopes
     */
    protected function makeApi(
        string $identifier,
        array $scopes = [],
        ?string $organizationId = null,
        ?string $clientId = null,
        string $name = 'Test API',
    ): Api {
        $definitions = [];

        foreach ($scopes as $key => $value) {
            if (is_string($key)) {
                $definitions[] = new ApiScopeDefinition($key, tenantRequestable: $value === true);
            } elseif (is_string($value)) {
                $definitions[] = new ApiScopeDefinition($value);
            }
        }

        return app(Apis::class)->register(new NewApi($identifier, $name, $organizationId, $clientId, $definitions));
    }

    /**
     * Declare a host-served protected resource (`cbox-id.oauth.protected_resources`) for
     * the rest of the test — an MCP endpoint at `{issuer}/mcp`, by default.
     *
     * @param  list<string>  $scopes
     * @return array<string, mixed> the declaration, as config holds it
     */
    protected function declareProtectedResource(
        string $path = '/mcp',
        array $scopes = ['mcp:tools'],
        bool $dynamicClients = true,
        ?string $identifier = null,
        ?string $name = null,
    ): array {
        $declaration = array_filter([
            'path' => $identifier === null ? $path : null,
            'identifier' => $identifier,
            'name' => $name,
            'scopes' => $scopes,
            'dynamic_clients' => $dynamicClients,
        ], static fn (mixed $value): bool => $value !== null);

        $existing = config('cbox-id.oauth.protected_resources', []);

        config(['cbox-id.oauth.protected_resources' => [...(is_array($existing) ? $existing : []), $declaration]]);

        return $declaration;
    }

    /**
     * Turn client ID metadata documents on and answer every fetch from memory. Serve a
     * document with `->serve($url, [...])`; refuse one as the SSRF guard would with
     * `->refuseAsUnsafe($url)`.
     */
    protected function fakeClientMetadataDocuments(): FakeMetadataDocumentFetcher
    {
        config(['cbox-id.oauth.client_id_metadata_documents.enabled' => true]);

        $fetcher = new FakeMetadataDocumentFetcher;

        app()->instance(MetadataDocumentFetcher::class, $fetcher);

        // The documents service and everything holding it are singletons built with the
        // previous fetcher; drop them so the next resolve picks the fake up.
        foreach ([
            ClientIdMetadataDocuments::class,
            AuthorizationClients::class,
            ClientAssertion::class,
            ClientAuthenticator::class,
        ] as $abstract) {
            app()->forgetInstance($abstract);
        }

        return $fetcher;
    }
}
