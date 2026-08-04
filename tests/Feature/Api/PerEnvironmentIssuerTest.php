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

it('prefers a VERIFIED custom domain as the issuer', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'domain' => 'id.acme.com', 'domain_verified_at' => now(), 'is_default' => false]);

    expect(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://id.acme.com');
});

it('does NOT trust an UNVERIFIED custom domain as the issuer (R1 — no identity hijack)', function (): void {
    // A domain set by a routing/branding path without DNS proof must never become the
    // issuer — the env falls back to its {slug}.{base_domain} host.
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'domain' => 'id.victim.com', 'domain_verified_at' => null, 'is_default' => false]);

    expect(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://acme.cboxid.com');
});

it('uses the operator-set app.url (not the request host) for the issuer fallback', function (): void {
    // No configured issuer, no base domains, an UNVERIFIED custom domain: the fallback
    // must be the operator-set app.url — NEVER url('/'), which would echo the request
    // Host (the unverified domain that routed the request) and re-open the R1 gap.
    config(['cbox-id.issuer' => null, 'cbox-id.environments.base_domains' => [], 'app.url' => 'https://cboxid.com']);
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'domain' => 'id.victim.com', 'domain_verified_at' => null, 'is_default' => false]);

    expect(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://cboxid.com');
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

it('holds the §3.3 invariant on BOTH hosts an environment resolves on', function (): void {
    // The failure this exists for: a tenant onboarded at acme.cboxid.com later verifies
    // its own domain. It keeps resolving on the subdomain (slug match), so that host went
    // on serving a full protocol surface advertising `issuer: https://id.acme.com` — and
    // every relying party configured against the subdomain refused the document.
    Environment::create([
        'name' => 'Acme', 'slug' => 'acme', 'domain' => 'id.acme.com',
        'domain_verified_at' => now(), 'is_default' => false,
    ]);

    // The canonical host serves it, and names itself.
    $this->get('https://id.acme.com/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://id.acme.com');

    // The alias does not serve a contradicting document — it points at the one that does.
    $this->get('https://acme.cboxid.com/.well-known/openid-configuration')
        ->assertRedirect('https://id.acme.com/.well-known/openid-configuration')
        ->assertStatus(301);
});

it('redirects the whole IdP surface off a non-canonical alias, preserving method and query', function (): void {
    Environment::create([
        'name' => 'Acme', 'slug' => 'acme', 'domain' => 'id.acme.com',
        'domain_verified_at' => now(), 'is_default' => false,
    ]);

    $this->get('https://acme.cboxid.com/.well-known/jwks.json')
        ->assertRedirect('https://id.acme.com/.well-known/jwks.json');

    // 308, not 301: a client that rewrote POST /oauth/token to GET would drop the grant
    // body and be answered with a 405 instead of a token.
    $this->post('https://acme.cboxid.com/oauth/token?trace=1')
        ->assertRedirect('https://id.acme.com/oauth/token?trace=1')
        ->assertStatus(308);
});

it('leaves the platform root and the single-tenant shape on any host they answer', function (): void {
    // The root's issuer is operator-configured and host-independent, so a health probe,
    // an internal LB name or a second ingress must keep being served rather than bounced
    // at the public apex.
    Environment::create(['name' => 'Root', 'slug' => 'root', 'is_default' => true]);

    $this->get('https://internal-lb.cluster.local/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://cboxid.com');
});
