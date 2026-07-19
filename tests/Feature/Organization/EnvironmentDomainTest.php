<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Organization\Contracts\EnvironmentDomains;
use Cbox\Id\Organization\Exceptions\InvalidCustomDomain;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\ValueObjects\DomainChallenge;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.environments.base_domains' => ['cboxid.com']]);
    $this->dns = $this->fakeDns();
    app()->forgetInstance(EnvironmentDomains::class);
    app()->forgetInstance(IssuerResolver::class);
});

function domains(): EnvironmentDomains
{
    return app(EnvironmentDomains::class);
}

it('issues a DNS TXT challenge for a requested custom domain', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    $challenge = domains()->request($env->id, 'id.acme.com');

    expect($challenge)->toBeInstanceOf(DomainChallenge::class)
        ->and($challenge->domain)->toBe('id.acme.com')
        ->and($challenge->recordName)->toBe('_cbox-id-challenge.id.acme.com')
        ->and($challenge->recordValue)->toStartWith('cbox-id-domain-verification=')
        ->and($challenge->verified)->toBeFalse();

    // Requesting does NOT touch the live issuer host yet.
    expect($env->fresh()->domain)->toBeNull();
});

it('promotes the domain to the environment issuer once the TXT record is live', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    $challenge = domains()->request($env->id, 'id.acme.com');
    $this->dns->publish($challenge->recordName, $challenge->recordValue);

    $verified = domains()->verify($env->id);

    expect($verified->verified)->toBeTrue()
        ->and($env->fresh()->domain)->toBe('id.acme.com')
        ->and(domains()->challenge($env->id))->toBeNull();

    // The per-environment issuer now advertises the custom domain.
    expect(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://id.acme.com');
});

it('does not verify when the TXT record is absent or wrong', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);
    domains()->request($env->id, 'id.acme.com');

    // Nothing published → not verified, issuer host untouched.
    expect(domains()->verify($env->id)->verified)->toBeFalse()
        ->and($env->fresh()->domain)->toBeNull();

    // A wrong value (a different env's token) does not verify either.
    $this->dns->publish('_cbox-id-challenge.id.acme.com', 'cbox-id-domain-verification=not-the-token');
    expect(domains()->verify($env->id)->verified)->toBeFalse()
        ->and($env->fresh()->domain)->toBeNull();
});

it('refuses a malformed domain or a bare IP', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    expect(fn () => domains()->request($env->id, 'not a domain'))->toThrow(InvalidCustomDomain::class);
    expect(fn () => domains()->request($env->id, '203.0.113.5'))->toThrow(InvalidCustomDomain::class);
});

it('refuses a platform-reserved base domain or its subdomain', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    expect(fn () => domains()->request($env->id, 'cboxid.com'))->toThrow(InvalidCustomDomain::class);
    expect(fn () => domains()->request($env->id, 'acme.cboxid.com'))->toThrow(InvalidCustomDomain::class);
});

it('refuses a domain already claimed by another environment', function (): void {
    Environment::create(['name' => 'Other', 'slug' => 'other', 'domain' => 'id.acme.com', 'is_default' => false]);
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);

    expect(fn () => domains()->request($env->id, 'id.acme.com'))->toThrow(InvalidCustomDomain::class);
});

it('clears a custom domain, falling the issuer back to the subdomain', function (): void {
    $env = Environment::create(['name' => 'Acme', 'slug' => 'acme', 'is_default' => false]);
    $challenge = domains()->request($env->id, 'id.acme.com');
    $this->dns->publish($challenge->recordName, $challenge->recordValue);
    domains()->verify($env->id);

    domains()->clear($env->id);

    expect($env->fresh()->domain)->toBeNull()
        ->and(app(IssuerResolver::class)->forEnvironment($env->id))->toBe('https://acme.cboxid.com');
});
