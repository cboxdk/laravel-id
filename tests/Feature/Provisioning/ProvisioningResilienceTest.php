<?php

declare(strict_types=1);

use Cbox\Id\Provisioning\Contracts\ProvisioningService;
use Cbox\Id\Provisioning\Enums\OperationStatus;
use Cbox\Id\Provisioning\Models\ProvisionedResource;
use Cbox\Id\Provisioning\Models\ProvisioningOperation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);
});

it('retries a transient failure with backoff, then dead-letters at the cap', function (): void {
    config(['cbox-id.provisioning.max_attempts' => 2]);
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    $user = $this->makeUser('gina@example.com', 'Gina');
    $this->relayEvents();

    // Every attempt fails at the transport layer (a genuinely transient fault).
    $fake->failTransport(times: 10, connectionId: $connection->id);

    // First attempt → failed, backed off to a future next_attempt_at.
    app(ProvisioningService::class)->drainConnection($connection->id);
    $operation = ProvisioningOperation::query()->where('user_id', $user->id)->firstOrFail();
    expect($operation->status)->toBe(OperationStatus::Failed)
        ->and($operation->attempt)->toBe(1)
        ->and($operation->next_attempt_at)->not->toBeNull()
        // The secret is never written into a stored error.
        ->and((string) $operation->last_error)->not->toContain('downstream-token');

    // Make it due and drain again → second (final) attempt hits the cap.
    $operation->update(['next_attempt_at' => now()->subMinute()]);
    app(ProvisioningService::class)->drainConnection($connection->id);

    $operation->refresh();
    expect($operation->status)->toBe(OperationStatus::Exhausted)
        ->and($operation->attempt)->toBe(2)
        ->and($operation->next_attempt_at)->toBeNull();
});

it('opens the per-connection circuit breaker after repeated failures and pauses delivery', function (): void {
    config([
        'cbox-id.provisioning.max_attempts' => 20,          // don't dead-letter first
        'cbox-id.provisioning.circuit_breaker.failure_threshold' => 2,
    ]);
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    // Two queued operations, both failing.
    $this->makeUser('h1@example.com');
    $this->makeUser('h2@example.com');
    $this->relayEvents();
    $fake->failWith(500, times: 10, connectionId: $connection->id);

    app(ProvisioningService::class)->drainConnection($connection->id);

    // Two consecutive failures tripped the breaker.
    $connection->refresh();
    expect($connection->consecutive_failures)->toBeGreaterThanOrEqual(2)
        ->and($connection->circuit_opened_at)->not->toBeNull();

    // With the breaker open, a further drain makes NO calls and delivers nothing,
    // even though operations are still pending.
    $callsBefore = count($fake->requests);
    $delivered = app(ProvisioningService::class)->drainConnection($connection->id);
    expect($delivered)->toBe(0)
        ->and(count($fake->requests))->toBe($callsBefore);
});

it('never lets a failing connection block a healthy one', function (): void {
    $fake = $this->fakeScimClient();
    $healthy = $this->registerProvisioningConnection(name: 'Healthy')->connection;
    $broken = $this->registerProvisioningConnection(name: 'Broken')->connection;

    // One user.created enqueues an operation for BOTH env-wide connections.
    $user = $this->makeUser('ivan@example.com', 'Ivan');
    $this->relayEvents();

    // Only the broken connection fails.
    $fake->failWith(500, times: 10, connectionId: $broken->id);

    app(ProvisioningService::class)->drainConnection($broken->id);
    app(ProvisioningService::class)->drainConnection($healthy->id);

    // The healthy connection provisioned the user despite the other being down.
    expect(ProvisionedResource::query()->where('connection_id', $healthy->id)->where('user_id', $user->id)->exists())->toBeTrue()
        ->and(ProvisionedResource::query()->where('connection_id', $broken->id)->where('user_id', $user->id)->exists())->toBeFalse();
});

it('reconstructs the connection environment in a worker with no ambient environment', function (): void {
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    $user = $this->makeUser('jane@example.com', 'Jane');
    $this->relayEvents();

    // Simulate a bare queue worker: no ambient environment at all.
    $this->forgetEnvironment();

    // The job reads the connection's environment_id under withoutScope, re-enters
    // it via runAs, and delivers — deny-by-default would otherwise see nothing.
    $this->drainProvisioning($connection->id);

    // Re-enter the environment to assert the outcome.
    $this->actingAsEnvironment('env_test');
    expect(ProvisionedResource::query()->where('connection_id', $connection->id)->where('user_id', $user->id)->exists())->toBeTrue()
        ->and($fake->requestsOfType('create'))->toHaveCount(1);
});
