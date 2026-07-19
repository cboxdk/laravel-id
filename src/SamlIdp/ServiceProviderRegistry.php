<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\ValueObjects\NewServiceProvider;
use Illuminate\Support\Collection;

/**
 * Database-backed registry of relying SAML service providers. Every read is
 * automatically constrained to the current environment by the model's
 * {@see BelongsToEnvironment} scope, so an SP is
 * only ever resolvable within the environment it was registered in.
 */
final class ServiceProviderRegistry implements ServiceProviders
{
    public function register(NewServiceProvider $serviceProvider): ServiceProvider
    {
        return ServiceProvider::query()->create([
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
    }

    public function findByEntityId(string $entityId): ?ServiceProvider
    {
        if ($entityId === '') {
            return null;
        }

        return ServiceProvider::query()->where('entity_id', $entityId)->first();
    }

    public function findActiveByEntityId(string $entityId): ?ServiceProvider
    {
        $serviceProvider = $this->findByEntityId($entityId);

        return $serviceProvider !== null && $serviceProvider->isActive() ? $serviceProvider : null;
    }

    public function findById(string $id): ?ServiceProvider
    {
        if ($id === '') {
            return null;
        }

        return ServiceProvider::query()->find($id);
    }

    public function all(): Collection
    {
        return ServiceProvider::query()->orderBy('entity_id')->get();
    }
}
