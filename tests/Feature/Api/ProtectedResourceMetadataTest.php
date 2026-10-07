<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\ConfiguredProtectedResources;
use Cbox\Id\OAuthServer\Contracts\ProtectedResources;
use Cbox\Id\OAuthServer\Exceptions\InvalidProtectedResource;
use Cbox\Id\OAuthServer\Support\BearerChallenge;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * RFC 9728: the root document describing the issuer as a resource, a host-declared
 * resource's document at its path-suffixed well-known URL, and the `resource_metadata`
 * parameter of the WWW-Authenticate challenge that points a client at it.
 */

function prmIssuer(): string
{
    return rtrim(app(IssuerResolver::class)->issuer(), '/');
}

it('serves a declared resource at the well-known URL with its path appended', function (): void {
    $this->declareProtectedResource('/mcp', ['mcp:tools', 'mcp:admin'], name: 'MCP');

    $this->getJson('/.well-known/oauth-protected-resource/mcp')
        ->assertOk()
        ->assertExactJson([
            'resource' => prmIssuer().'/mcp',
            'authorization_servers' => [app(IssuerResolver::class)->issuer()],
            'scopes_supported' => ['mcp:tools', 'mcp:admin', 'offline_access'],
            'bearer_methods_supported' => ['header'],
            'resource_name' => 'MCP',
        ]);
});

it('serves a nested resource path, and 404s a path nothing is declared at', function (): void {
    $this->declareProtectedResource('/api/mcp/v1', ['mcp:tools']);

    $this->getJson('/.well-known/oauth-protected-resource/api/mcp/v1')
        ->assertOk()
        ->assertJsonPath('resource', prmIssuer().'/api/mcp/v1');

    // Never another resource's document in its place (RFC 9728 §3.3).
    $this->getJson('/.well-known/oauth-protected-resource/api/mcp')->assertNotFound();
    $this->getJson('/.well-known/oauth-protected-resource/nothing-here')->assertNotFound();
});

it('keeps the root document, with scopes_supported read from the resolver', function (): void {
    $this->getJson('/.well-known/oauth-protected-resource')
        ->assertOk()
        ->assertJsonPath('resource', app(IssuerResolver::class)->issuer())
        ->assertJsonPath('scopes_supported', ['openid', 'profile', 'email', 'offline_access', 'organizations', 'groups']);
});

it('lets a host that rebinds the resolver change what the root document advertises', function (): void {
    $this->app->singleton(ProtectedResources::class, fn () => new class(app(IssuerResolver::class)) extends ConfiguredProtectedResources
    {
        public function issuerScopes(): array
        {
            return ['openid', 'decisions:read'];
        }
    });

    $this->getJson('/.well-known/oauth-protected-resource')
        ->assertOk()
        ->assertJsonPath('scopes_supported', ['openid', 'decisions:read']);
});

it('advertises the scopes of resources open to self-registered clients in discovery', function (): void {
    $this->declareProtectedResource('/mcp', ['mcp:tools']);
    $this->declareProtectedResource('/internal', ['internal:ops'], dynamicClients: false);

    $scopes = $this->getJson('/.well-known/oauth-authorization-server')->assertOk()->json('scopes_supported');

    expect($scopes)->toContain('mcp:tools')
        ->not->toContain('internal:ops');
});

it('builds the RFC 9728 metadata URL by inserting the well-known suffix before the path', function (): void {
    $resource = new ProtectedResource('https://h.example.test/mcp');
    $root = new ProtectedResource('https://h.example.test');
    $port = new ProtectedResource('https://h.example.test:8443/tools/mcp/');

    expect($resource->metadataUrl())->toBe('https://h.example.test/.well-known/oauth-protected-resource/mcp')
        ->and($root->metadataUrl())->toBe('https://h.example.test/.well-known/oauth-protected-resource')
        ->and($port->metadataUrl())->toBe('https://h.example.test:8443/.well-known/oauth-protected-resource/tools/mcp');
});

it('refuses a declaration it could not serve', function (string $identifier): void {
    expect(fn () => new ProtectedResource($identifier))->toThrow(InvalidProtectedResource::class);
})->with([
    'plain http off loopback' => 'http://h.example.test/mcp',
    'query' => 'https://h.example.test/mcp?x=1',
    'fragment' => 'https://h.example.test/mcp#x',
    'credentials' => 'https://u:p@h.example.test/mcp',
    'relative' => '/mcp',
]);

it('refuses a declared resource that claims a protocol scope or an invalid one', function (): void {
    expect(fn () => new ProtectedResource('https://h.example.test/mcp', ['openid']))->toThrow(InvalidProtectedResource::class)
        ->and(fn () => new ProtectedResource('https://h.example.test/mcp', ['has space']))->toThrow(InvalidProtectedResource::class);
});

it('refuses a config entry with neither an identifier nor a path', function (): void {
    config(['cbox-id.oauth.protected_resources' => [['scopes' => ['mcp:tools']]]]);

    expect(fn () => app(ProtectedResources::class)->all())->toThrow(InvalidProtectedResource::class);
});

it('builds a WWW-Authenticate challenge carrying resource_metadata', function (): void {
    $resource = new ProtectedResource('https://h.example.test/mcp', ['mcp:tools']);

    expect(BearerChallenge::for($resource)->header())
        ->toBe('Bearer resource_metadata="https://h.example.test/.well-known/oauth-protected-resource/mcp"');

    expect(BearerChallenge::for($resource)->withError('insufficient_scope', 'needs "more"')->withScopes(['mcp:tools'])->header())
        ->toBe('Bearer resource_metadata="https://h.example.test/.well-known/oauth-protected-resource/mcp", error="insufficient_scope", error_description="needs \"more\"", scope="mcp:tools"');

    expect((new BearerChallenge)->header())->toBe('Bearer')
        ->and(BearerChallenge::for($resource)->withScheme('DPoP')->headers())
        ->toBe(['WWW-Authenticate' => 'DPoP resource_metadata="https://h.example.test/.well-known/oauth-protected-resource/mcp"']);
});

it('points a refused UserInfo request at the root protected resource metadata', function (): void {
    $header = (string) $this->getJson('/oauth/userinfo')->assertStatus(401)->headers->get('WWW-Authenticate');

    expect($header)->toStartWith('Bearer ')
        ->toContain('resource_metadata="'.prmIssuer().'/.well-known/oauth-protected-resource"')
        ->toContain('error="invalid_token"');
});

it('points a refused decision request at the root protected resource metadata, escaped', function (): void {
    $header = (string) $this->postJson('/oauth/decisions', [])->assertStatus(401)->headers->get('WWW-Authenticate');

    expect($header)->toContain('resource_metadata="'.prmIssuer().'/.well-known/oauth-protected-resource"');
});
