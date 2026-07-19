<?php

declare(strict_types=1);

use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

beforeEach(fn () => config([
    'cbox-id.environments.base_domains' => ['cboxid.com'],
    'cbox-id.issuer' => 'https://cboxid.com',
]));

it('resolves a tenant environment issuer from its {slug}.{base_domain}', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    expect(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://acme.cboxid.com');
});

it('prefers a custom domain as the issuer when set', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'domain' => 'id.acme.com', 'is_default' => false]);

    expect(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://id.acme.com');
});

it('keeps the configured issuer for the platform-root environment', function (): void {
    $env = Environment::create(['name' => 'Root', 'slug' => 'root', 'is_default' => true]);

    expect(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://cboxid.com');
});

it('falls back to the configured issuer for an unknown environment', function (): void {
    expect(app(IssuerResolver::class)->forEnvironment('env_does_not_exist'))->toBe('https://cboxid.com');
});

it('makes discovery, id_token and access-token issuers agree per environment', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    $this->runAsEnvironment($env->id, function (): void {
        $issuer = app(IssuerResolver::class)->issuer();

        // discovery `issuer` + `jwks_uri` are the environment's own host…
        expect($issuer)->toBe('https://acme.cboxid.com')
            ->and(ServerMetadata::issuer())->toBe($issuer)
            ->and(ServerMetadata::document()['jwks_uri'])->toBe('https://acme.cboxid.com/.well-known/jwks.json')
            ->and(ServerMetadata::document()['issuer'])->toBe($issuer);
    });
});

it('serves OIDC discovery with the per-environment issuer at a tenant subdomain', function (): void {
    Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    // RFC 8414 §3.3: the issuer MUST equal the host the document was fetched from.
    $this->get('https://acme.cboxid.com/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.cboxid.com')
        ->assertJsonPath('jwks_uri', 'https://acme.cboxid.com/.well-known/jwks.json')
        ->assertJsonPath('token_endpoint', 'https://acme.cboxid.com/oauth/token');
});
