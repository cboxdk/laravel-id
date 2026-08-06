<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Provisioning\Models\ProvisionedResource;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);
});

it('reconciles a 409-on-create by matching the existing remote via externalId', function (): void {
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    $user = $this->makeUser('erin@example.com', 'Erin');

    // The user already exists on the downstream app (a prior partial sync or
    // out-of-band creation) under a known remote id, keyed by our externalId.
    $fake->seedRemote($connection->id, $user->id, 'remote-existing-123');

    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    // The create hit 409; instead of duplicating we located the existing record
    // by externalId and PATCHed it — the captured remote id is the existing one.
    expect($fake->requestsOfType('create'))->toHaveCount(1)
        ->and($fake->requestsOfType('find'))->toHaveCount(1)
        ->and($fake->requestsOfType('patch'))->toHaveCount(1);

    $provisioned = ProvisionedResource::query()->where('user_id', $user->id)->firstOrFail();
    expect($provisioned->remote_id)->toBe('remote-existing-123');

    // No duplicate: only the seeded record exists remotely.
    expect($fake->remote[$connection->id])->toHaveCount(1);
});

it('recreates on a 404-on-update when the remote record was deleted out-of-band', function (): void {
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    $user = $this->makeUser('frank@example.com', 'Frank');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);
    $firstRemoteId = ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id');

    // The downstream app deletes the record; our next PATCH will 404.
    $fake->dropRemote($connection->id, $firstRemoteId);

    app(EventBus::class)->emit(new DomainEvent('user.updated', ['user_id' => $user->id]));
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    // The 404 triggered a recreate (a second create), capturing a fresh remote id.
    expect($fake->requestsOfType('create'))->toHaveCount(2);

    $newRemoteId = ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id');
    expect($newRemoteId)->not->toBeNull()
        ->and($newRemoteId)->not->toBe($firstRemoteId);
});
