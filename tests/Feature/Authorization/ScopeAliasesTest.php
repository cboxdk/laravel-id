<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\Contracts\ScopeAliases;
use Cbox\Id\Kernel\Authorization\NoScopeAliases;
use Cbox\Id\Kernel\Authorization\Support\Scopes;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Cbox\Id\Platform\Models\EnvironmentApiKey;
use Cbox\Id\Platform\Models\OrganizationApiKey;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/** A host registry that renamed one scope. */
function bindRenamedScope(): void
{
    app()->instance(ScopeAliases::class, new class implements ScopeAliases
    {
        public function canonical(string $scope): string
        {
            return ['workspace:read' => 'id:organization:read'][$scope] ?? $scope;
        }
    });
}

it('binds no aliases by default, so a scope is only itself', function (): void {
    expect(app(ScopeAliases::class))->toBeInstanceOf(NoScopeAliases::class)
        ->and(Scopes::satisfies(['workspace:read'], 'id:organization:read'))->toBeFalse()
        ->and(Scopes::satisfies(['workspace:read'], 'workspace:read'))->toBeTrue()
        ->and(Scopes::canonicalise(['workspace:read', 'openid']))->toBe(['workspace:read', 'openid']);
});

it('treats an old and a new name as one scope in every check', function (): void {
    bindRenamedScope();

    $token = Introspection::active('u1', 'cid_1', ['workspace:read'], []);
    $client = (new Client)->forceFill(['scopes' => ['workspace:read']]);
    $environmentKey = (new EnvironmentApiKey)->forceFill(['scopes' => ['workspace:read']]);
    $organizationKey = (new OrganizationApiKey)->forceFill(['scopes' => ['id:organization:read']]);

    expect($token->hasScope('id:organization:read'))->toBeTrue()
        ->and($token->hasScope('workspace:read'))->toBeTrue()
        ->and($token->hasScope('id:members:read'))->toBeFalse()
        ->and($client->allows('id:organization:read'))->toBeTrue()
        ->and($environmentKey->can('id:organization:read'))->toBeTrue()
        ->and($organizationKey->permits('workspace:read'))->toBeTrue()
        ->and($organizationKey->permits('id:members:read'))->toBeFalse();
});

it('grants the new name to a client that asks for the old one', function (): void {
    bindRenamedScope();
    $registered = $this->makeClient(['workspace:read']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'workspace:read',
    ])->assertOk();

    expect($response->json('scope'))->toBe('id:organization:read');
});

it('grants a client registered under the old name the new one it asks for', function (): void {
    bindRenamedScope();
    $registered = $this->makeClient(['workspace:read']);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'id:organization:read',
    ])->assertOk();

    // RFC 6749 §5.1: `scope` is echoed only when it differs from what was asked for.
    expect($response->json('scope') ?? 'id:organization:read')->toBe('id:organization:read');
});
