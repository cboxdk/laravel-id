<?php

declare(strict_types=1);

use Cbox\Id\Federation\Exceptions\OidcDiscoveryFailed;
use Cbox\Id\Federation\OidcDiscovery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

const ISSUER = 'https://idp.okta.example';

function discoveryDoc(array $overrides = []): array
{
    return array_merge([
        'issuer' => ISSUER,
        'authorization_endpoint' => ISSUER.'/oauth2/authorize',
        'token_endpoint' => ISSUER.'/oauth2/token',
        'jwks_uri' => ISSUER.'/oauth2/keys',
        'userinfo_endpoint' => ISSUER.'/oauth2/userinfo',
    ], $overrides);
}

beforeEach(function (): void {
    // Disable URL enforcement so the fake host isn't DNS-resolved (as the flow tests do).
    config(['cbox-id.federation.verify_url' => false]);
});

it('resolves the endpoints from an issuer through the SSRF gate', function (): void {
    Http::fake([ISSUER.'/.well-known/openid-configuration' => Http::response(discoveryDoc(), 200)]);

    $provider = app(OidcDiscovery::class)->fromIssuer(ISSUER);

    expect($provider->authorizationEndpoint)->toBe(ISSUER.'/oauth2/authorize')
        ->and($provider->tokenEndpoint)->toBe(ISSUER.'/oauth2/token')
        ->and($provider->jwksUri)->toBe(ISSUER.'/oauth2/keys')
        ->and($provider->isComplete())->toBeTrue();

    // toConfig() carries exactly the keys the OIDC client reads.
    expect($provider->toConfig())->toMatchArray([
        'issuer' => ISSUER,
        'authorization_endpoint' => ISSUER.'/oauth2/authorize',
        'token_endpoint' => ISSUER.'/oauth2/token',
    ]);
});

it('tolerates a trailing slash on the issuer', function (): void {
    Http::fake([ISSUER.'/.well-known/openid-configuration' => Http::response(discoveryDoc(), 200)]);

    $provider = app(OidcDiscovery::class)->fromIssuer(ISSUER.'/');

    expect($provider->issuer)->toBe(ISSUER)->and($provider->isComplete())->toBeTrue();
});

it('rejects a discovery document whose issuer does not match', function (): void {
    Http::fake([ISSUER.'/.well-known/openid-configuration' => Http::response(
        discoveryDoc(['issuer' => 'https://attacker.example']), 200,
    )]);

    expect(fn () => app(OidcDiscovery::class)->fromIssuer(ISSUER))
        ->toThrow(OidcDiscoveryFailed::class, 'does not match');
});

it('rejects a discovery document missing the token endpoint', function (): void {
    Http::fake([ISSUER.'/.well-known/openid-configuration' => Http::response(
        ['issuer' => ISSUER, 'authorization_endpoint' => ISSUER.'/oauth2/authorize'], 200,
    )]);

    expect(fn () => app(OidcDiscovery::class)->fromIssuer(ISSUER))
        ->toThrow(OidcDiscoveryFailed::class, 'missing the authorization or token endpoint');
});

it('surfaces an HTTP error from the discovery URL', function (): void {
    Http::fake([ISSUER.'/.well-known/openid-configuration' => Http::response('nope', 404)]);

    expect(fn () => app(OidcDiscovery::class)->fromIssuer(ISSUER))
        ->toThrow(OidcDiscoveryFailed::class, 'HTTP 404');
});

it('rejects an empty issuer', function (): void {
    expect(fn () => app(OidcDiscovery::class)->fromIssuer('  '))
        ->toThrow(OidcDiscoveryFailed::class, 'issuer was empty');
});
