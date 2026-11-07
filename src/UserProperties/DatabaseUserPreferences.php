<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\UserProperties\Contracts\UserPreferences;
use Cbox\Id\UserProperties\Models\PropertyNamespace;
use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Cbox\Id\UserProperties\ValueObjects\PropertySnapshot;
use Illuminate\Support\Facades\DB;

class DatabaseUserPreferences implements UserPreferences
{
    use ResolvesEnvironment;

    public function __construct(private readonly PropertyDocuments $documents) {}

    public function read(string $userId): PropertySnapshot
    {
        return $this->documents->read($userId, 'preferences');
    }

    public function patch(string $userId, PropertyPatch $patch): PropertySnapshot
    {
        $this->environments()->requireEnvironment();

        return DB::transaction(function () use ($userId, $patch): PropertySnapshot {
            // Establish the shared lock row without granting any app access.
            PropertyNamespace::query()->firstOrCreate(['name' => 'preferences'], [
                'readers' => [], 'writers' => [], 'webhooks' => [],
            ]);
            PropertyNamespace::query()->where('name', 'preferences')->lockForUpdate()->firstOrFail();

            return $this->documents->patch(null, $userId, 'preferences', $patch);
        });
    }
}
