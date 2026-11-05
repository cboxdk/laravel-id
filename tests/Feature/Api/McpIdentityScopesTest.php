<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientIdMetadataDocuments;
use Cbox\Id\OAuthServer\Support\SelfRegisteredScopes;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'mcp']);
    $this->declareProtectedResource('/mcp', ['mcp:read', 'mcp:write']);
});

it('registers the OIDC scopes ChatGPT adds when registration omits scope', function (): void {
    $response = $this->postJson('/oauth/register', [
        'client_name' => 'ChatGPT',
        'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
    ])->assertCreated();

    expect(explode(' ', (string) $response->json('scope')))->toEqualCanonicalizing([
        'mcp:read', 'mcp:write', 'openid', 'profile', 'email', 'offline_access',
    ]);
});

it('allows the same OIDC scopes for a metadata document without scope', function (): void {
    $url = 'https://chatgpt.com/oauth/client.json';
    $this->fakeClientMetadataDocuments()->serve($url, [
        'client_id' => $url,
        'client_name' => 'ChatGPT',
        'redirect_uris' => ['https://chatgpt.com/connector_platform_oauth_redirect'],
        'grant_types' => ['authorization_code', 'refresh_token'],
        'token_endpoint_auth_method' => 'none',
    ]);

    expect(app(ClientIdMetadataDocuments::class)->resolve($url)->scopes)->toEqualCanonicalizing([
        'mcp:read', 'mcp:write', 'openid', 'profile', 'email', 'offline_access',
    ]);
});

it('keeps default identity scopes within the operator allow-list', function (): void {
    config(['cbox-id.oauth.dynamic_registration.allowed_scopes' => ['openid', 'offline_access']]);

    expect(app(SelfRegisteredScopes::class)->defaults(true))->toEqualCanonicalizing([
        'mcp:read', 'mcp:write', 'openid', 'offline_access',
    ]);
});

it('does not add identity scopes to an explicit scope registration', function (): void {
    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Read only',
        'redirect_uris' => ['https://client.example.test/callback'],
        'scope' => 'mcp:read',
    ])->assertCreated();

    expect($response->json('scope'))->toBe('mcp:read');
});

it('does not default to identity extensions or refresh without its grant', function (): void {
    expect(app(SelfRegisteredScopes::class)->defaults(false))->toEqualCanonicalizing([
        'mcp:read', 'mcp:write', 'openid', 'profile', 'email',
    ]);
});
