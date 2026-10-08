<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

it('passes the health check on a configured install', function (): void {
    config([
        'cbox-id.issuer' => 'https://id.acme.test',
        'cbox-id.webauthn.rp_id' => 'id.acme.test',
        'cbox-id.webauthn.origin' => 'https://id.acme.test',
        // A fully-configured OIDC install advertises where /authorize is mounted;
        // without it discovery omits a field OIDC Discovery §3 marks REQUIRED.
        'cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize',
    ]);
    // A fully-configured install has a platform root stamped in the DATABASE — that is
    // what `cbox-id:install` does, and it is what stops the answer depending on
    // per-process configuration in a horizontally-scaled deployment.
    $root = Environment::query()->create([
        'name' => 'Platform',
        'slug' => 'platform-root',
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => true,
        'settings' => [],
    ]);

    // Its signing key, minted where a real install mints it: in that environment.
    $this->runAsEnvironment($root->id, fn () => app(KeyManager::class)->activeSigningKey());

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

it('counts signing keys per environment, past the environment scope, and names one without', function (): void {
    $environment = static fn (string $slug): Environment => Environment::query()->create([
        'name' => ucfirst($slug),
        'slug' => $slug,
        'type' => EnvironmentType::Production,
        'status' => EnvironmentStatus::Active,
        'is_default' => false,
    ]);

    $alpha = $environment('alpha');
    $beta = $environment('beta');
    $keys = app(KeyManager::class);

    // The doctor runs with NO environment set — the scope that hid every key from it.
    $this->runAsEnvironment($alpha->id, fn () => $keys->activeSigningKey());

    $this->artisan('cbox-id:doctor')->expectsOutputToContain('No active signing key yet in: beta');

    $this->runAsEnvironment($beta->id, fn () => $keys->activeSigningKey());

    $this->artisan('cbox-id:doctor')->expectsOutputToContain('Every environment (2) has an active key');
});
