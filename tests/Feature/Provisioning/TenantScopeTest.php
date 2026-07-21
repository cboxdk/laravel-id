<?php

declare(strict_types=1);

use Cbox\Id\Provisioning\Contracts\ProvisioningConnections;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Enums\EndpointStatus;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Http::fake();
    // No real DNS in tests; the SSRF guard is exercised in its own suite.
    config(['cbox-id.provisioning.verify_url' => false, 'cbox-id.webhooks.verify_url' => false]);
});

/**
 * @group isolation
 *
 * Two modules the round-2 IDOR sweep did not reach. Both hand one tenant a lever over
 * another's data: provisioning pushes user email/name to a customer-controlled SCIM
 * endpoint, and webhooks deliver every domain event to a customer-controlled URL.
 */
it('confines a tenant-owned provisioning connection to its own organization', function (): void {
    $registered = app(ProvisioningConnections::class)->register(
        'org_a',
        'Acme SCIM',
        'https://scim.acme.example',
        AuthScheme::Bearer,
        'secret-token',
        organizationIds: ['org_b'],   // asking for ANOTHER tenant's users
    );

    $connection = $registered->connection->refresh();

    // The request is confined to the owner, not honoured.
    expect($connection->scopeOrganizationIds())->toBe(['org_a'])
        ->and($connection->isEnvironmentWide())->toBeFalse();
});

it('does not read an empty tenant scope as environment-wide', function (): void {
    $tenant = app(ProvisioningConnections::class)->register(
        'org_a', 'Acme', 'https://scim.acme.example', AuthScheme::Bearer, 's',
        organizationIds: [],          // empty used to mean "every org in the environment"
    );

    expect($tenant->connection->refresh()->isEnvironmentWide())->toBeFalse();

    // A PLATFORM-owned connection legitimately covers the environment.
    $platform = app(ProvisioningConnections::class)->register(
        null, 'Platform', 'https://scim.platform.example', AuthScheme::Bearer, 's',
        organizationIds: [],
    );

    expect($platform->connection->refresh()->isEnvironmentWide())->toBeTrue();
});

it('refuses to pause another organization\'s webhook endpoint', function (): void {
    $victim = app(WebhookRegistry::class)->register('org_b', 'https://hooks.b.example', ['user.created']);
    $platform = app(WebhookRegistry::class)->register(null, 'https://hooks.platform.example', ['user.created']);

    // Org A knows the ids and tries both.
    app(WebhookRegistry::class)->pause($victim->endpoint->id, 'org_a');
    app(WebhookRegistry::class)->pause($platform->endpoint->id, 'org_a');

    expect(WebhookEndpoint::query()->whereKey($victim->endpoint->id)->value('status'))
        ->toBe(EndpointStatus::Active)
        ->and(WebhookEndpoint::query()->whereKey($platform->endpoint->id)->value('status'))
        ->toBe(EndpointStatus::Active);

    // The rightful owner still can.
    app(WebhookRegistry::class)->pause($victim->endpoint->id, 'org_b');

    expect(WebhookEndpoint::query()->whereKey($victim->endpoint->id)->value('status'))
        ->toBe(EndpointStatus::Paused);
});
