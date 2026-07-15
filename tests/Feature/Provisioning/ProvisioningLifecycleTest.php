<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;
use Cbox\Id\Provisioning\Enums\ResourceState;
use Cbox\Id\Provisioning\Models\ProvisionedResource;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

// These tests target the provisioning flow, not the SSRF guard (covered
// separately); registration and delivery run offline against the fake server.
beforeEach(function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);
});

it('provisions a created user with a POST /Users carrying the real SCIM 2.0 shape', function (): void {
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    // A real user.created event flows through the bus → listener → outbox.
    $user = $this->makeUser('alice@example.com', 'Alice Example');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    // Exactly one create, with the RFC 7643 §4.1 User resource shape.
    $creates = $fake->requestsOfType('create');
    expect($creates)->toHaveCount(1);

    $resource = $creates[0]['resource'];
    expect($resource['schemas'])->toBe([ScimSchema::USER_URN])
        ->and($resource['externalId'])->toBe($user->id)
        ->and($resource['userName'])->toBe('alice@example.com')
        ->and($resource['active'])->toBeTrue()
        ->and($resource['displayName'])->toBe('Alice Example')
        ->and($resource['emails'][0]['value'])->toBe('alice@example.com')
        ->and($resource['emails'][0]['primary'])->toBeTrue();

    // The remote id is captured, so we never re-create this user.
    $provisioned = ProvisionedResource::query()->where('user_id', $user->id)->firstOrFail();
    expect($provisioned->remote_id)->not->toBeNull()
        ->and($provisioned->external_id)->toBe($user->id)
        ->and($provisioned->state)->toBe(ResourceState::Active);
});

it('updates a user by PATCHing the captured remote id with a real PatchOp body', function (): void {
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    $user = $this->makeUser('bob@example.com', 'Bob');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);
    $remoteId = ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id');

    // A subsequent update targets the same remote resource with PATCH, not POST.
    app(EventBus::class)->emit(new DomainEvent('user.updated', ['user_id' => $user->id]));
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    $patches = $fake->requestsOfType('patch');
    expect($patches)->toHaveCount(1)
        ->and($patches[0]['remoteId'])->toBe($remoteId)
        ->and($fake->requestsOfType('create'))->toHaveCount(1); // still just the one create

    // Every PatchOp operation is a well-formed `replace` (RFC 7644 §3.5.2.3).
    foreach ($patches[0]['operations'] as $operation) {
        expect($operation['op'])->toBe('replace')
            ->and($operation)->toHaveKey('path');
    }
});

it('deactivates a user with PATCH replace active=false', function (): void {
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection()->connection;

    $user = $this->makeUser('carol@example.com', 'Carol');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);
    $remoteId = ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id');

    // Deactivation via the Subjects contract emits user.deactivated.
    app(Subjects::class)->deactivate($user->id);
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    $patches = $fake->requestsOfType('patch');
    expect($patches)->toHaveCount(1)
        ->and($patches[0]['remoteId'])->toBe($remoteId);

    // The deactivation op is exactly `{op: replace, path: active, value: false}`.
    $activeOps = array_values(array_filter(
        $patches[0]['operations'],
        fn (array $op): bool => ($op['path'] ?? null) === 'active',
    ));
    expect($activeOps)->toHaveCount(1)
        ->and($activeOps[0])->toBe(['op' => 'replace', 'path' => 'active', 'value' => false]);

    expect(ProvisionedResource::query()->where('user_id', $user->id)->value('state'))
        ->toBe(ResourceState::Deactivated);
});

it('de-provisions a removed member by DELETE when the policy is delete', function (): void {
    $fake = $this->fakeScimClient();
    $organization = $this->makeOrganization('Northwind');
    $connection = $this->registerProvisioningConnection(
        organizationIds: [$organization->id],
        deprovisionPolicy: DeprovisionPolicy::Delete,
    )->connection;

    $user = $this->makeUser('dan@example.com', 'Dan');
    app(Memberships::class)->add($organization->id, $user->id, 'member');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);
    $remoteId = ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id');
    expect($remoteId)->not->toBeNull();

    // Removing the membership de-provisions via DELETE /Users/{id}.
    app(Memberships::class)->remove($organization->id, $user->id);
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    $deletes = $fake->requestsOfType('delete');
    expect($deletes)->toHaveCount(1)
        ->and($deletes[0]['remoteId'])->toBe($remoteId)
        ->and(ProvisionedResource::query()->where('user_id', $user->id)->value('state'))
        ->toBe(ResourceState::Deprovisioned);
});

it('does NOT deprovision a member removed from one org while still in another org the same connection covers', function (): void {
    $fake = $this->fakeScimClient();
    $orgA = $this->makeOrganization('Alpha');
    $orgB = $this->makeOrganization('Beta');
    // ONE connection covering BOTH orgs, with the destructive Delete policy.
    $connection = $this->registerProvisioningConnection(
        organizationIds: [$orgA->id, $orgB->id],
        deprovisionPolicy: DeprovisionPolicy::Delete,
    )->connection;

    $user = $this->makeUser('eve@example.com', 'Eve');
    app(Memberships::class)->add($orgA->id, $user->id, 'member');
    app(Memberships::class)->add($orgB->id, $user->id, 'member');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);
    expect(ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id'))->not->toBeNull();

    // Remove from orgA ONLY — the user is still a member of orgB, which this same
    // connection provisions, so they must NOT be DELETEd/deactivated downstream.
    app(Memberships::class)->remove($orgA->id, $user->id);
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    expect($fake->requestsOfType('delete'))->toHaveCount(0)
        ->and(ProvisionedResource::query()->where('user_id', $user->id)->value('state'))
        ->toBe(ResourceState::Active);
});

it('does NOT deprovision from an environment-wide connection on an org membership removal', function (): void {
    $fake = $this->fakeScimClient();
    $org = $this->makeOrganization('Gamma');
    // An environment-wide connection (no org scope) covers every subject.
    $connection = $this->registerProvisioningConnection(
        organizationIds: [],
        deprovisionPolicy: DeprovisionPolicy::Delete,
    )->connection;

    $user = $this->makeUser('frank@example.com', 'Frank');
    app(Memberships::class)->add($org->id, $user->id, 'member');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);
    expect(ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id'))->not->toBeNull();

    // An org removal never removes the user from the ENVIRONMENT, so an env-wide
    // connection keeps them — no DELETE.
    app(Memberships::class)->remove($org->id, $user->id);
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    expect($fake->requestsOfType('delete'))->toHaveCount(0)
        ->and(ProvisionedResource::query()->where('user_id', $user->id)->value('state'))
        ->toBe(ResourceState::Active);
});
