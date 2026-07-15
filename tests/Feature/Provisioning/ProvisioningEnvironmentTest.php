<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Provisioning\Models\ProvisionedResource;
use Cbox\Id\Provisioning\Models\ProvisioningOperation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

beforeEach(function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);
});

/**
 * @group isolation
 *
 * Dispatch stage: a change occurring in env_b never enqueues an operation for a
 * connection that lives in env_a. The enqueue reads env-owned connections
 * deny-by-default, so the env_a connection is invisible from env_b.
 */
it('never enqueues an env-B change against an env-A connection', function (): void {
    $connectionA = $this->runAsEnvironment('env_a', fn () => $this->registerProvisioningConnection(name: 'A')->connection);

    // A user.created occurring while acting as env_b.
    $this->runAsEnvironment('env_b', function (): void {
        app(EventBus::class)->emit(new DomainEvent('user.created', ['user_id' => 'user_from_b', 'email' => 'b@example.com']));
        app(EventBus::class)->flushPending();
    });

    // No operation was written for the env_a connection.
    $opsForA = $this->runAsEnvironment('env_a', fn () => ProvisioningOperation::query()
        ->where('connection_id', $connectionA->id)->count());
    expect($opsForA)->toBe(0);

    // And env_b, having no connection, wrote nothing at all.
    $opsInB = $this->runAsEnvironment('env_b', fn () => ProvisioningOperation::query()->count());
    expect($opsInB)->toBe(0);
});

/**
 * @group isolation
 *
 * Drain stage: the drain of an env_a connection — running inside the
 * reconstructed env_a — only ever loads and delivers env_a's operations. An
 * env_b operation on an env_b connection is never touched.
 */
it('drains only the connection environment and leaves other environments untouched', function (): void {
    $fake = $this->fakeScimClient();

    // A connection + a queued user.created in each environment.
    $connectionA = $this->runAsEnvironment('env_a', function () {
        $connection = $this->registerProvisioningConnection(name: 'A')->connection;
        app(EventBus::class)->emit(new DomainEvent('user.created', ['user_id' => 'user_a', 'email' => 'a@example.com']));
        app(EventBus::class)->flushPending();

        return $connection;
    });

    $connectionB = $this->runAsEnvironment('env_b', function () {
        $connection = $this->registerProvisioningConnection(name: 'B')->connection;
        app(EventBus::class)->emit(new DomainEvent('user.created', ['user_id' => 'user_b', 'email' => 'b@example.com']));
        app(EventBus::class)->flushPending();

        return $connection;
    });

    // Drain ONLY env_a's connection (the job reconstructs env_a internally).
    $this->drainProvisioning($connectionA->id);

    // env_a's operation delivered; env_b's is still pending and never provisioned.
    $aOps = $this->runAsEnvironment('env_a', fn () => ProvisionedResource::query()->where('connection_id', $connectionA->id)->count());
    $bOps = $this->runAsEnvironment('env_b', fn () => ProvisionedResource::query()->where('connection_id', $connectionB->id)->count());

    expect($aOps)->toBe(1)
        ->and($bOps)->toBe(0);

    // The fake only ever saw env_a's connection.
    $connectionsCalled = array_unique(array_column($fake->requests, 'connection'));
    expect($connectionsCalled)->toBe([$connectionA->id]);
});
