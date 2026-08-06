<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('passes the health check on a configured install', function (): void {
    config([
        'cbox-id.issuer' => 'https://id.acme.test',
        'cbox-id.webauthn.rp_id' => 'id.acme.test',
        'cbox-id.webauthn.origin' => 'https://id.acme.test',
        // A fully-configured OIDC install advertises where /authorize is mounted;
        // without it discovery omits a field OIDC Discovery §3 marks REQUIRED.
        'cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize',
    ]);
    app(KeyManager::class)->activeSigningKey(); // mint a signing key

    // A fully-configured install has a platform root stamped in the DATABASE — that is
    // what `cbox-id:install` does, and it is what stops the answer depending on
    // per-process configuration in a horizontally-scaled deployment.
    Environment::query()->create([
        'name' => 'Platform',
        'slug' => 'platform-root',
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => true,
        'settings' => [],
    ]);

    $this->artisan('cbox-id:doctor')
        ->assertExitCode(0)
        ->expectsOutputToContain('Crypto master key')
        ->expectsOutputToContain('Signing keys')
        ->expectsOutputToContain('healthy');
});

it('warns (but does not fail) when passkeys and issuer are unconfigured', function (): void {
    config(['cbox-id.issuer' => null, 'cbox-id.webauthn.rp_id' => null, 'cbox-id.webauthn.origin' => null]);

    // Warnings only -> still a success exit code.
    $this->artisan('cbox-id:doctor')->assertExitCode(0);
});

it('fails when the crypto master key is missing', function (): void {
    config(['cbox-id.crypto.key' => null]);

    $this->artisan('cbox-id:doctor')
        ->expectsOutputToContain('Crypto master key')
        ->assertExitCode(1);
});

it('fails production hardening when sessions are insecure', function (): void {
    app()['env'] = 'production';
    config(['app.debug' => true, 'session.secure' => false, 'session.encrypt' => false]);

    $this->artisan('cbox-id:doctor')
        ->expectsOutputToContain('Production hardening')
        ->assertExitCode(1);
});
