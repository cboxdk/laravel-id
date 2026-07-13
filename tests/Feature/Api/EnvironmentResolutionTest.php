<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Environment::create(['name' => 'Staging', 'slug' => 'staging', 'domain' => 'id.staging.acme.com']);
});

it('resolves an environment from a custom domain', function (): void {
    $env = app(EnvironmentResolver::class)->resolveForHost('id.staging.acme.com');

    expect($env?->environmentKey())->toBe(Environment::where('slug', 'staging')->value('id'));
});

it('resolves an environment from the leading subdomain label under a configured base domain', function (): void {
    config(['cbox-id.environments.base_domains' => ['auth.example.com']]);

    $env = app(EnvironmentResolver::class)->resolveForHost('staging.auth.example.com');

    expect($env?->slug)->toBe('staging');
});

it('refuses a spoofed host that is not under a configured base domain', function (): void {
    config(['cbox-id.environments.base_domains' => ['auth.example.com']]);

    // A matching leading label but the wrong parent domain must NOT select a plane.
    expect(app(EnvironmentResolver::class)->resolveForHost('staging.attacker.com'))->toBeNull();
});

it('refuses subdomain-slug resolution entirely when no base domain is configured', function (): void {
    config(['cbox-id.environments.base_domains' => []]);

    expect(app(EnvironmentResolver::class)->resolveForHost('staging.auth.example.com'))->toBeNull();
});

it('resolves nothing for an unknown host', function (): void {
    expect(app(EnvironmentResolver::class)->resolveForHost('nope.example.com'))->toBeNull();
});

it('refuses a request whose host maps to no environment and no default', function (): void {
    config(['cbox-id.environments.default' => null]);

    $this->getJson('http://stranger.example.com/up')->assertStatus(404);
});

it('serves a request on a resolved environment host', function (): void {
    config(['cbox-id.environments.default' => null]);

    $this->getJson('http://id.staging.acme.com/up')->assertOk();
});
