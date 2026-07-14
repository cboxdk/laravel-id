<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    // Isolate .env writes to a throwaway file so install never pollutes the
    // shared test environment (issuer/app-url leaking into other tests).
    $this->tmpEnvDir = sys_get_temp_dir().'/cboxid-env-'.uniqid();
    mkdir($this->tmpEnvDir);
    file_put_contents($this->tmpEnvDir.'/.env', '');
    $this->app->useEnvironmentPath($this->tmpEnvDir);
});

afterEach(function (): void {
    @unlink($this->tmpEnvDir.'/.env');
    @rmdir($this->tmpEnvDir);
});

it('bootstraps the platform: answers questions, applies config, mints a signing key', function (): void {
    // Clear the test harness's explicit default so the install command exercises
    // the database-flag path (the mechanism a real fresh install uses).
    config(['cbox-id.environments.default' => null]);

    $this->artisan('cbox-id:install')
        ->expectsQuestion('Public URL of this identity platform (the token issuer)', 'https://id.acme.test')
        ->expectsQuestion('Passkey domain (WebAuthn rp_id)', 'id.acme.test')
        ->expectsQuestion('Passkey origin (WebAuthn origin)', 'https://id.acme.test')
        ->expectsQuestion('Name your first environment (its own users, keys and issuer)', 'Production')
        ->assertExitCode(0);

    // Exactly one environment is created and flagged the default in the DB (not
    // an env var).
    $default = Environment::query()->where('is_default', true)->get();
    expect($default)->toHaveCount(1)
        ->and($default->first()->slug)->toBe('production')
        ->and(config('cbox-id.issuer'))->toBe('https://id.acme.test')
        ->and(config('cbox-id.webauthn.rp_id'))->toBe('id.acme.test');

    // The first signing key is minted INSIDE the new environment's scope, so it
    // is only visible from within that environment — proof the bootstrap ran
    // scoped, not globally.
    $activeKeys = app(EnvironmentContext::class)->runAs(
        $default->first(),
        fn (): int => SigningKey::query()->where('status', KeyStatus::Active->value)->count(),
    );
    expect($activeKeys)->toBeGreaterThan(0);
});

it('generates a crypto master key at runtime when none is set', function (): void {
    config(['cbox-id.crypto.key' => null]);
    $this->app->forgetInstance(SecretBox::class);

    $this->artisan('cbox-id:install')
        ->expectsQuestion('Public URL of this identity platform (the token issuer)', 'https://id.acme.test')
        ->expectsQuestion('Passkey domain (WebAuthn rp_id)', 'id.acme.test')
        ->expectsQuestion('Passkey origin (WebAuthn origin)', 'https://id.acme.test')
        ->expectsQuestion('Name your first environment (its own users, keys and issuer)', 'Production')
        ->assertExitCode(0);

    // A fresh 32-byte key (44 base64 chars) was generated and written to .env.
    $env = (string) file_get_contents($this->app->environmentFilePath());
    expect($env)->toMatch('/CBOX_ID_CRYPTO_KEY=\S{43,}/');
});
