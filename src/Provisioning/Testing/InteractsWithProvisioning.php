<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Testing;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Provisioning\Contracts\ProvisioningConnections;
use Cbox\Id\Provisioning\Contracts\ScimClient;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;
use Cbox\Id\Provisioning\Jobs\DrainProvisioningConnection;
use Cbox\Id\Provisioning\ValueObjects\RegisteredConnection;

/**
 * Test ergonomics for outbound provisioning. Ships with the package so a host
 * gets the same fluency: bind an in-memory {@see FakeScimClient} as the SCIM
 * transport, register an env-owned connection (stamped with the current test
 * environment automatically), and drive the drain the way the async job does.
 */
trait InteractsWithProvisioning
{
    protected ?FakeScimClient $fakeScimClient = null;

    /**
     * Swap the real HTTP {@see ScimClient} for an in-memory fake downstream SCIM
     * server, so lifecycle assertions run without HTTP.
     */
    protected function fakeScimClient(): FakeScimClient
    {
        $fake = $this->fakeScimClient ??= new FakeScimClient;

        app()->instance(ScimClient::class, $fake);

        return $fake;
    }

    /**
     * Register a provisioning connection in the current environment.
     *
     * @param  list<string>  $organizationIds  empty ⇒ environment-wide
     * @param  array<string, mixed>  $attributeMapping
     * @param  array<string, mixed>  $authConfig
     */
    protected function registerProvisioningConnection(
        ?string $organizationId = null,
        string $name = 'Downstream App',
        string $baseUrl = 'https://scim.downstream.test/scim/v2',
        AuthScheme $authScheme = AuthScheme::Bearer,
        string $secret = 'downstream-token',
        array $attributeMapping = [],
        array $organizationIds = [],
        DeprovisionPolicy $deprovisionPolicy = DeprovisionPolicy::Deactivate,
        array $authConfig = [],
    ): RegisteredConnection {
        return app(ProvisioningConnections::class)->register(
            $organizationId,
            $name,
            $baseUrl,
            $authScheme,
            $secret,
            $attributeMapping,
            $organizationIds,
            $deprovisionPolicy,
            $authConfig,
        );
    }

    /** Drain one connection the way the async job does (reconstructing its environment). */
    protected function drainProvisioning(string $connectionId): void
    {
        DrainProvisioningConnection::dispatchSync($connectionId);
    }

    /**
     * Relay the domain-event outbox so `EventDelivered` fires and the provisioning
     * listener enqueues operations — the request-side of the flow, synchronously.
     */
    protected function relayEvents(): void
    {
        app(EventBus::class)->flushPending();
    }
}
