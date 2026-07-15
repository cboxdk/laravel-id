<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Contracts;

use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\ValueObjects\NewServiceProvider;
use Illuminate\Support\Collection;

/**
 * The registry of relying SAML service providers for the current environment. It
 * is the single source of truth the IdP consults to decide whether it will issue
 * an assertion to a given SP, and where. A lookup that misses returns null and the
 * caller refuses — the registry never invents an SP.
 */
interface ServiceProviders
{
    public function register(NewServiceProvider $serviceProvider): ServiceProvider;

    /**
     * The registered SP for an EntityID, or null if none exists in this
     * environment. Does NOT filter by status — callers decide whether a
     * disabled SP is acceptable (issuance requires active; management does not).
     */
    public function findByEntityId(string $entityId): ?ServiceProvider;

    /**
     * The active SP for an EntityID, or null if none is registered or it is not
     * active. This is the gate issuance uses.
     */
    public function findActiveByEntityId(string $entityId): ?ServiceProvider;

    public function findById(string $id): ?ServiceProvider;

    /**
     * @return Collection<int, ServiceProvider>
     */
    public function all(): Collection;
}
