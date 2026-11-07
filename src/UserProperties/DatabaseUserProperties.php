<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\UserProperties\Contracts\UserProperties;
use Cbox\Id\UserProperties\Models\PropertyNamespace;
use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Cbox\Id\UserProperties\ValueObjects\PropertySnapshot;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\DB;

class DatabaseUserProperties implements UserProperties
{
    use ResolvesEnvironment;

    public function __construct(private readonly PropertyDocuments $documents) {}

    public function read(string $clientId, string $userId, string $namespace): PropertySnapshot
    {
        $this->authorize($clientId, $namespace, false);

        return $this->documents->read($userId, $namespace);
    }

    public function patch(string $clientId, string $userId, string $namespace, PropertyPatch $patch): PropertySnapshot
    {
        return DB::transaction(function () use ($clientId, $userId, $namespace, $patch): PropertySnapshot {
            $this->authorize($clientId, $namespace, true);

            return $this->documents->patch($clientId, $userId, $namespace, $patch);
        });
    }

    private function authorize(string $clientId, string $namespace, bool $write): void
    {
        $this->environments()->requireEnvironment();
        $query = PropertyNamespace::query()->where('name', $namespace);
        $record = ($write ? $query->lockForUpdate() : $query)->first();
        if ($record === null || ! in_array($clientId, $record->readers, true)
            || ($write && ! in_array($clientId, $record->writers, true))
            || ! Client::query()->where('client_id', $clientId)->whereNull('organization_id')->exists()) {
            throw new AuthorizationException('This app cannot access this namespace.');
        }
    }
}
