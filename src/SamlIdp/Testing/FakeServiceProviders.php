<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Testing;

use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\ValueObjects\NewServiceProvider;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * In-memory {@see ServiceProviders} registry for host apps that want to exercise
 * the SAML IdP without a database. Bind it in a test:
 * `app()->instance(ServiceProviders::class, new FakeServiceProviders())`.
 */
final class FakeServiceProviders implements ServiceProviders
{
    /** @var array<string, ServiceProvider> keyed by model id */
    private array $providers = [];

    public function register(NewServiceProvider $serviceProvider): ServiceProvider
    {
        $model = new ServiceProvider;
        $model->forceFill([
            'id' => (string) Str::ulid(),
            'environment_id' => 'fake',
            'entity_id' => $serviceProvider->entityId,
            'acs_url' => $serviceProvider->acsUrl,
            'slo_url' => $serviceProvider->sloUrl,
            'name_id_format' => $serviceProvider->nameIdFormat,
            'name_id_attribute' => $serviceProvider->nameIdAttribute,
            'attribute_mappings' => $serviceProvider->attributeMappings,
            'certificate' => $serviceProvider->certificate,
            'want_authn_requests_signed' => $serviceProvider->wantAuthnRequestsSigned,
            'status' => $serviceProvider->status,
        ]);

        $this->providers[$model->id] = $model;

        return $model;
    }

    public function findByEntityId(string $entityId): ?ServiceProvider
    {
        foreach ($this->providers as $provider) {
            if ($provider->entity_id === $entityId) {
                return $provider;
            }
        }

        return null;
    }

    public function findActiveByEntityId(string $entityId): ?ServiceProvider
    {
        $provider = $this->findByEntityId($entityId);

        return $provider !== null && $provider->isActive() ? $provider : null;
    }

    public function findById(string $id): ?ServiceProvider
    {
        return $this->providers[$id] ?? null;
    }

    public function all(): Collection
    {
        return new Collection(array_values($this->providers));
    }
}
