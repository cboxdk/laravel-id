<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Provisioning\Contracts\ProvisioningConnections;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Exceptions\UnsafeScimUrl;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\Provisioning\Models\ProvisioningOperation;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

it('is deny-by-default: with no connection configured, a change makes no outbound call', function (): void {
    Http::fake();
    $fake = $this->fakeScimClient();

    // A user is created, but no connection exists in the environment.
    $this->makeUser('kate@example.com', 'Kate');
    $this->relayEvents();

    // Nothing enqueued, nothing sent.
    expect(ProvisioningOperation::query()->count())->toBe(0)
        ->and($fake->requests)->toBe([]);
    Http::assertNothingSent();
});

it('refuses to register a connection pointed at a private/metadata address (SSRF)', function (): void {
    // The SSRF guard is ON (the real guard from cboxdk/laravel-ssrf).
    config(['cbox-id.provisioning.verify_url' => true]);

    expect(fn () => $this->registerProvisioningConnection(baseUrl: 'http://169.254.169.254/scim/v2'))
        ->toThrow(UnsafeScimUrl::class);

    expect(ProvisioningConnection::query()->count())->toBe(0);
});

it('stores the connection secret as ciphertext at rest, never the raw token', function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);

    $connection = app(ProvisioningConnections::class)->register(
        organizationId: null,
        name: 'Downstream',
        baseUrl: 'https://scim.downstream.test/scim/v2',
        authScheme: AuthScheme::Bearer,
        secret: 'super-secret-bearer-token',
    )->connection;

    // The stored column is sealed — the raw token never appears in it, and the
    // value is bound to this connection's context (a different context won't open).
    expect($connection->auth_secret_encrypted)->not->toContain('super-secret-bearer-token')
        ->and($connection->auth_secret_encrypted)->not->toBe('super-secret-bearer-token');

    $opened = app(SecretBox::class)
        ->open($connection->auth_secret_encrypted, $connection->secretContext());
    expect($opened)->toBe('super-secret-bearer-token');
});
