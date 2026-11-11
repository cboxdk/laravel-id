<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\RelyingParties;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/*
 * THE TENANT BASE DOMAIN IS NOT THE ROOT'S DOMAIN.
 *
 * A platform root on one registrable domain (`login.cboxid.com`) with its customers'
 * environments on another (`{slug}.cboxauth.com`) — so a tenant's sign-in page can never
 * share a site, a cookie scope or a passkey RP suffix with the platform's own.
 *
 * It is configuration, and this pins the two facts the configuration rests on: the FIRST
 * base domain is the canonical tenant base, and the root's issuer is `cbox-id.issuer`,
 * derived from no base domain at all. A base domain that is being moved away from stays
 * in the list after the canonical one: it still resolves, and its metadata redirects.
 */
beforeEach(function (): void {
    config([
        'cbox-id.issuer' => 'https://login.cboxid.com',
        'cbox-id.environments.base_domains' => ['cboxauth.com', 'cboxid.com'],
        'cbox-id.webauthn.rp_id' => null,
        'cbox-id.webauthn.origin' => null,
    ]);

    $this->root = Environment::create(['name' => 'Cbox', 'slug' => 'cbox', 'is_default' => true]);
    $this->tenant = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);
});

it('issues a tenant environment from the canonical tenant base, not the root’s domain', function (): void {
    expect(app(IssuerResolver::class)->forEnvironment($this->tenant->id))->toBe('https://acme.cboxauth.com');

    $this->get('https://acme.cboxauth.com/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://acme.cboxauth.com')
        ->assertJsonPath('token_endpoint', 'https://acme.cboxauth.com/oauth/token');
});

it('keeps the root on its configured issuer, whatever the tenant base is', function (): void {
    expect(app(IssuerResolver::class)->forEnvironment($this->root->id))->toBe('https://login.cboxid.com');

    // `login.cboxid.com` names no environment by slug, so it is the default one — and the
    // root has no canonical host of its own, so nothing redirects it anywhere.
    $this->get('https://login.cboxid.com/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://login.cboxid.com');
});

it('still resolves a tenant on the old base domain, and redirects its metadata to the canonical one', function (): void {
    expect(app(EnvironmentResolver::class)->resolveForHost('acme.cboxid.com')?->environmentKey())->toBe($this->tenant->id)
        ->and(app(EnvironmentResolver::class)->resolveForHost('acme.cboxauth.com')?->environmentKey())->toBe($this->tenant->id);

    $this->get('https://acme.cboxid.com/.well-known/openid-configuration')
        ->assertRedirect('https://acme.cboxauth.com/.well-known/openid-configuration');
});

it('scopes a tenant’s passkeys to its own host on the tenant base, and the root’s to the issuer', function (): void {
    $tenant = $this->runAsEnvironment($this->tenant->id, fn () => app(RelyingParties::class)->current());
    $root = $this->runAsEnvironment($this->root->id, fn () => app(RelyingParties::class)->current());

    expect($tenant->id)->toBe('acme.cboxauth.com')
        ->and($tenant->origin)->toBe('https://acme.cboxauth.com')
        ->and($root->id)->toBe('login.cboxid.com')
        ->and($root->origin)->toBe('https://login.cboxid.com');
});

it('does not let a host under neither base domain select an environment by slug', function (): void {
    expect(app(EnvironmentResolver::class)->resolveForHost('acme.attacker.com'))->toBeNull();
});
