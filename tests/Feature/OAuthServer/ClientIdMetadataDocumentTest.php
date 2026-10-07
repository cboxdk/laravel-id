<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Contracts\AuthorizationClients;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\ClientIdMetadataDocuments;
use Cbox\Id\OAuthServer\Contracts\MetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadataDocument;
use Cbox\Id\OAuthServer\HttpMetadataDocumentFetcher;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\MetadataDocumentClient;
use Cbox\Id\OAuthServer\Testing\FakeMetadataDocumentFetcher;
use Cbox\Ssrf\Testing\InteractsWithSsrf;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class, InteractsWithSsrf::class);

/*
 * Client ID Metadata Documents: an https `client_id` whose JSON document is the client's
 * registration. Every rule the document is held to is driven here, and the fetch itself
 * is driven both through the in-memory fake and through the real SSRF-guarded fetcher
 * against faked DNS — a document URL that resolves inward must never be requested.
 */

const CIMD_URL = 'https://client.example.test/oauth/metadata.json';

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function cimdDocument(array $overrides = []): array
{
    return array_merge([
        'client_id' => CIMD_URL,
        'client_name' => 'Example MCP Client',
        'client_uri' => 'https://client.example.test',
        'logo_uri' => 'https://client.example.test/logo.png',
        'redirect_uris' => ['http://127.0.0.1:33418/callback', 'https://client.example.test/callback'],
        'grant_types' => ['authorization_code', 'refresh_token'],
        'response_types' => ['code'],
        'token_endpoint_auth_method' => 'none',
    ], $overrides);
}

function cimdMcp(): string
{
    return rtrim(app(IssuerResolver::class)->issuer(), '/').'/mcp';
}

/**
 * @return array<string, mixed>
 */
function cimdClaims(string $jwt): array
{
    return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
}

/**
 * Mint a code for the document client the way /authorize does, then redeem it.
 *
 * @param  list<string>  $scopes
 * @param  array<string, string>  $extra
 */
function cimdRedeem(array $scopes, ?string $resource, array $extra = []): TestResponse
{
    $verifier = str_repeat('c', 64);

    $code = app(AuthorizationCodes::class)->issue(
        CIMD_URL,
        'alice',
        null,
        'https://client.example.test/callback',
        $scopes,
        Base64Url::encode(hash('sha256', $verifier, true)),
        resource: $resource,
    );

    return test()->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => CIMD_URL,
        'code' => $code,
        'redirect_uri' => 'https://client.example.test/callback',
        'code_verifier' => $verifier,
        ...$extra,
    ]);
}

function cimdReason(callable $call): ?string
{
    try {
        $call();
    } catch (InvalidClientMetadataDocument $e) {
        return $e->reason;
    }

    return null;
}

beforeEach(function (): void {
    $this->declareProtectedResource('/mcp', ['mcp:tools']);
});

// ---------------------------------------------------------------------------------------
// Off by default.
// ---------------------------------------------------------------------------------------

it('is off by default: a URL client_id is an unknown client and nothing is fetched', function (): void {
    $fetcher = new FakeMetadataDocumentFetcher;
    app()->instance(MetadataDocumentFetcher::class, $fetcher);

    expect(app(AuthorizationClients::class)->resolve(CIMD_URL))->toBeNull()
        ->and(app(ClientIdMetadataDocuments::class)->supports(CIMD_URL))->toBeFalse()
        ->and(cimdReason(fn () => app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL)))->toBe('disabled')
        ->and($fetcher->fetched)->toBe([]);

    config(['cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize']);
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonMissingPath('client_id_metadata_document_supported');
});

it('advertises client_id_metadata_document_supported when on', function (): void {
    $this->fakeClientMetadataDocuments();
    config(['cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize']);

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('client_id_metadata_document_supported', true);
});

// ---------------------------------------------------------------------------------------
// The happy path, end to end.
// ---------------------------------------------------------------------------------------

it('resolves a document client for /authorize with the consent facts the host shows', function (): void {
    $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument());

    $authorizing = app(AuthorizationClients::class)->resolve(CIMD_URL);

    expect($authorizing)->not->toBeNull()
        ->and($authorizing->isMetadataDocumentClient())->toBeTrue()
        ->and($authorizing->documentHost)->toBe('client.example.test')
        ->and($authorizing->clientUri)->toBe('https://client.example.test')
        ->and($authorizing->logoUri)->toBe('https://client.example.test/logo.png')
        ->and($authorizing->consentRequired())->toBeTrue()
        ->and($authorizing->client)->toBeInstanceOf(MetadataDocumentClient::class)
        ->and($authorizing->client->type)->toBe(ClientType::Public)
        ->and($authorizing->client->name)->toBe('Example MCP Client')
        // The scopes a self-registered client may hold here: the open resource's, plus
        // offline_access because it may refresh.
        ->and($authorizing->client->scopes)->toBe(['mcp:tools', 'offline_access'])
        ->and($authorizing->client->isDynamicallyRegistered())->toBeTrue();

    // Redirect URIs match EXACTLY — a loopback URI on another port is not the same one.
    expect($authorizing->allowsRedirectUri('http://127.0.0.1:33418/callback'))->toBeTrue()
        ->and($authorizing->allowsRedirectUri('http://127.0.0.1:40000/callback'))->toBeFalse()
        ->and($authorizing->allowsRedirectUri('https://client.example.test/callback/'))->toBeFalse();

    // Never persisted.
    expect(Client::query()->where('client_id', CIMD_URL)->exists())->toBeFalse()
        ->and(fn () => $authorizing->client->save())->toThrow(LogicException::class);
});

it('redeems a code for a document client, audienced to the requested resource', function (): void {
    $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument());

    $response = cimdRedeem(['mcp:tools', 'offline_access'], cimdMcp())->assertOk();
    $claims = cimdClaims($response->json('access_token'));

    expect($claims['aud'])->toBe(cimdMcp())
        ->and($claims['client_id'])->toBe(CIMD_URL)
        ->and($claims['scope'])->toBe('mcp:tools offline_access');

    // …and refreshes, still bound to the resource.
    $refreshed = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => CIMD_URL,
        'refresh_token' => $response->json('refresh_token'),
    ])->assertOk();

    expect(cimdClaims($refreshed->json('access_token'))['aud'])->toBe(cimdMcp());
});

it('refuses a document client a resource that does not accept self-registered clients', function (): void {
    config(['cbox-id.oauth.protected_resources' => []]);
    $this->declareProtectedResource('/admin', ['admin:all'], dynamicClients: false);
    $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument(['scope' => 'admin:all']));

    $client = app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL);

    // The scope is not even registered for it…
    expect($client->scopes)->toBe([]);

    // …and the audience is refused outright.
    expect(fn () => app(AudienceResolver::class)->resolve($client, [], rtrim(app(IssuerResolver::class)->issuer(), '/').'/admin'))
        ->toThrow(InvalidAudience::class);
});

it('narrows the scope a document asks for to what a self-registered client may hold', function (): void {
    $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument(['scope' => 'mcp:tools vault.manage openid unknown:x']));

    expect(app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL)->scopes)->toBe(['mcp:tools', 'openid']);
});

it('refuses a secret presented with a document client_id', function (): void {
    $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument());

    cimdRedeem(['mcp:tools'], cimdMcp(), ['client_secret' => 'anything'])
        ->assertStatus(401)
        ->assertJsonPath('error', 'invalid_client');
});

it('authenticates a private_key_jwt document client by assertion only, with keys from jwks_uri', function (): void {
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    openssl_pkey_export($key, $pem);
    $details = openssl_pkey_get_details($key);
    $jwk = [
        'kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'cimd-1',
        'n' => Base64Url::encode($details['rsa']['n']), 'e' => Base64Url::encode($details['rsa']['e']),
    ];

    $this->fakeClientMetadataDocuments()
        ->serve(CIMD_URL, cimdDocument(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks_uri' => 'https://client.example.test/jwks.json']))
        ->serve('https://client.example.test/jwks.json', ['keys' => [$jwk]]);

    expect(app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL)->type)->toBe(ClientType::Confidential);

    // A code alone does not redeem for a client that declared a key.
    cimdRedeem(['mcp:tools'], cimdMcp())->assertStatus(401)->assertJsonPath('error', 'invalid_client');

    $assertion = JWT::encode([
        'iss' => CIMD_URL,
        'sub' => CIMD_URL,
        'aud' => rtrim(app(IssuerResolver::class)->issuer(), '/').'/oauth/token',
        'jti' => bin2hex(random_bytes(16)),
        'iat' => time(),
        'exp' => time() + 60,
    ], (string) $pem, 'RS256', 'cimd-1');

    cimdRedeem(['mcp:tools'], cimdMcp(), [
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => $assertion,
    ])->assertOk();
});

// ---------------------------------------------------------------------------------------
// Caching.
// ---------------------------------------------------------------------------------------

it('caches the document for its max-age, within the configured bounds', function (): void {
    $fetcher = $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument(), maxAge: 300);
    $documents = app(ClientIdMetadataDocuments::class);

    $documents->resolve(CIMD_URL);
    $documents->resolve(CIMD_URL);
    expect($fetcher->fetched)->toHaveCount(1);

    $this->travel(301)->seconds();
    $documents->resolve(CIMD_URL);
    expect($fetcher->fetched)->toHaveCount(2);
});

it('holds no-store to the minimum and a huge max-age to the maximum', function (): void {
    config([
        'cbox-id.oauth.client_id_metadata_documents.min_ttl' => 60,
        'cbox-id.oauth.client_id_metadata_documents.max_ttl' => 600,
    ]);
    $fetcher = $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument(), maxAge: 0);
    $documents = app(ClientIdMetadataDocuments::class);

    $documents->resolve(CIMD_URL);
    $documents->resolve(CIMD_URL);
    expect($fetcher->fetched)->toHaveCount(1);

    $this->travel(61)->seconds();
    $fetcher->serve(CIMD_URL, cimdDocument(), maxAge: 31536000);
    $documents->resolve(CIMD_URL);
    expect($fetcher->fetched)->toHaveCount(2);

    $this->travel(601)->seconds();
    $documents->resolve(CIMD_URL);
    expect($fetcher->fetched)->toHaveCount(3);
});

// ---------------------------------------------------------------------------------------
// Every validation failure.
// ---------------------------------------------------------------------------------------

it('refuses a document that breaks a rule', function (array $overrides, string $reason, array $remove = []): void {
    $document = cimdDocument($overrides);

    foreach ($remove as $field) {
        unset($document[$field]);
    }

    $this->fakeClientMetadataDocuments()->serve(CIMD_URL, $document);

    expect(cimdReason(fn () => app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL)))->toBe($reason);
})->with([
    'client_id is another URL' => [['client_id' => 'https://evil.example.test/oauth/metadata.json'], 'client_id_mismatch'],
    'client_id differs by a trailing slash' => [['client_id' => CIMD_URL.'/'], 'client_id_mismatch'],
    'client_id missing' => [[], 'client_id_mismatch', ['client_id']],
    'client_secret present' => [['client_secret' => 's3cret'], 'prohibited_field'],
    'client_secret_expires_at present' => [['client_secret_expires_at' => 0], 'prohibited_field'],
    'shared-secret auth method' => [['token_endpoint_auth_method' => 'client_secret_basic'], 'invalid_auth_method'],
    'client_secret_post' => [['token_endpoint_auth_method' => 'client_secret_post'], 'invalid_auth_method'],
    'private_key_jwt without jwks_uri' => [['token_endpoint_auth_method' => 'private_key_jwt'], 'invalid_field'],
    'private_key_jwt with http jwks_uri' => [['token_endpoint_auth_method' => 'private_key_jwt', 'jwks_uri' => 'http://client.example.test/jwks'], 'invalid_field'],
    'inline jwks' => [['jwks' => ['keys' => []]], 'invalid_field'],
    'redirect_uris missing' => [[], 'invalid_field', ['redirect_uris']],
    'redirect_uris empty' => [['redirect_uris' => []], 'invalid_field'],
    'redirect_uris not a list' => [['redirect_uris' => 'https://client.example.test/cb'], 'invalid_field'],
    'plain http off loopback' => [['redirect_uris' => ['http://client.example.test/cb']], 'invalid_redirect_uri'],
    'redirect with a fragment' => [['redirect_uris' => ['https://client.example.test/cb#x']], 'invalid_redirect_uri'],
    'private-use scheme' => [['redirect_uris' => ['com.example.app:/cb']], 'invalid_redirect_uri'],
    'non-string redirect' => [['redirect_uris' => [42]], 'invalid_redirect_uri'],
    'grant_types without authorization_code' => [['grant_types' => ['client_credentials']], 'invalid_field'],
    'response_types without code' => [['response_types' => ['token']], 'invalid_field'],
    'scope not a string' => [['scope' => ['mcp:tools']], 'invalid_field'],
]);

it('refuses a private_key_jwt document whose jwks_uri serves no keys', function (): void {
    $this->fakeClientMetadataDocuments()
        ->serve(CIMD_URL, cimdDocument(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks_uri' => 'https://client.example.test/jwks.json']))
        ->serve('https://client.example.test/jwks.json', ['keys' => []]);

    expect(cimdReason(fn () => app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL)))->toBe('invalid_field');
});

it('keeps only the grants a document client may use', function (): void {
    $this->fakeClientMetadataDocuments()->serve(CIMD_URL, cimdDocument(['grant_types' => ['authorization_code', 'client_credentials']]));

    $client = app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL);

    expect($client->grant_types)->toBe(['authorization_code'])
        // No refresh grant, so no offline_access either.
        ->and($client->scopes)->toBe(['mcp:tools']);
});

it('refuses a client_id that is not a metadata document URL, without fetching', function (string $clientId): void {
    $fetcher = $this->fakeClientMetadataDocuments();

    expect(app(ClientIdMetadataDocuments::class)->supports($clientId))->toBeFalse()
        ->and(cimdReason(fn () => app(ClientIdMetadataDocuments::class)->resolve($clientId)))->toBe('invalid_client_id')
        ->and(app(AuthorizationClients::class)->resolve($clientId))->toBeNull()
        ->and($fetcher->fetched)->toBe([]);
})->with([
    'http' => 'http://client.example.test/metadata.json',
    'no path' => 'https://client.example.test',
    'root path' => 'https://client.example.test/',
    'dot segment' => 'https://client.example.test/a/../metadata.json',
    'single dot' => 'https://client.example.test/./metadata.json',
    'fragment' => 'https://client.example.test/metadata.json#x',
    'credentials' => 'https://user:pass@client.example.test/metadata.json',
    'too long' => 'https://client.example.test/'.str_repeat('a', 250),
]);

it('reports a document that cannot be fetched or parsed', function (InvalidClientMetadataDocument $failure, string $reason): void {
    $this->fakeClientMetadataDocuments()->fail(CIMD_URL, $failure);

    expect(cimdReason(fn () => app(ClientIdMetadataDocuments::class)->resolve(CIMD_URL)))->toBe($reason);
})->with([
    'unreachable' => [InvalidClientMetadataDocument::fetchFailed('HTTP 404'), 'fetch_failed'],
    'too large' => [InvalidClientMetadataDocument::tooLarge(5120), 'too_large'],
    'not json' => [InvalidClientMetadataDocument::notJson(), 'invalid_json'],
]);

// ---------------------------------------------------------------------------------------
// SSRF: an inward-pointing document URL is never requested.
// ---------------------------------------------------------------------------------------

it('refuses a document the SSRF guard refuses, and authenticates nobody with it', function (): void {
    $this->fakeClientMetadataDocuments()->refuseAsUnsafe(CIMD_URL);

    expect(cimdReason(fn () => app(AuthorizationClients::class)->resolve(CIMD_URL)))->toBe('unsafe_url');

    cimdRedeem(['mcp:tools'], cimdMcp())->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('never sends the request when the document host resolves to a private address', function (string $address): void {
    config(['cbox-id.oauth.client_id_metadata_documents.enabled' => true]);
    $this->fakeSsrfDns(['client.example.test' => [$address]]);
    Http::fake();

    expect(cimdReason(fn () => app(HttpMetadataDocumentFetcher::class)->fetch(CIMD_URL)))->toBe('unsafe_url');

    Http::assertNothingSent();
})->with([
    'loopback' => '127.0.0.1',
    'private' => '10.0.0.5',
    'link-local metadata service' => '169.254.169.254',
    'ipv6 loopback' => '::1',
]);

it('fetches a document from a public address through the real fetcher, reading its max-age', function (): void {
    $this->fakeSsrfDns(['client.example.test' => ['93.184.216.34']]);
    Http::fake([CIMD_URL => Http::response(cimdDocument(), 200, ['Cache-Control' => 'public, max-age=900'])]);

    $fetched = app(HttpMetadataDocumentFetcher::class)->fetch(CIMD_URL);

    expect($fetched->body['client_id'])->toBe(CIMD_URL)
        ->and($fetched->maxAge)->toBe(900);
});

it('refuses an oversized, non-JSON, redirecting or failing response through the real fetcher', function (mixed $body, int $status, array $headers, string $reason): void {
    $this->fakeSsrfDns(['client.example.test' => ['93.184.216.34']]);
    Http::fake([CIMD_URL => Http::response($body, $status, $headers)]);

    expect(cimdReason(fn () => app(HttpMetadataDocumentFetcher::class)->fetch(CIMD_URL)))->toBe($reason);
})->with([
    'too large' => [str_repeat('x', 5121), 200, [], 'too_large'],
    'not json' => ['<html></html>', 200, [], 'invalid_json'],
    'a json list' => [[1, 2, 3], 200, [], 'invalid_json'],
    'redirect' => ['', 302, ['Location' => 'http://169.254.169.254/'], 'fetch_failed'],
    'server error' => ['', 500, [], 'fetch_failed'],
]);
