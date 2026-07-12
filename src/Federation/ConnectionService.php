<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionStatus;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Illuminate\Support\Str;

final class ConnectionService implements Connections
{
    public function __construct(private readonly SecretBox $secretBox) {}

    public function create(
        string $organizationId,
        ConnectionType $type,
        string $name,
        array $config,
        array $mappings = [],
    ): Connection {
        $connection = new Connection;
        $connection->id = (string) Str::ulid();
        $connection->fill([
            'organization_id' => $organizationId,
            'type' => $type,
            'name' => $name,
            'status' => ConnectionStatus::Draft,
            'mappings' => $mappings,
        ]);
        $connection->config_encrypted = $this->secretBox->seal(
            json_encode($config, JSON_THROW_ON_ERROR),
            $connection->secretContext(),
        );
        $connection->save();

        return $connection;
    }

    public function byId(string $id): ?Connection
    {
        return Connection::query()->whereKey($id)->first();
    }

    public function forOrganization(string $organizationId): ?Connection
    {
        return Connection::query()
            ->where('organization_id', $organizationId)
            ->where('status', ConnectionStatus::Active->value)
            ->first();
    }

    public function activate(string $id): void
    {
        Connection::query()->whereKey($id)->first()?->update(['status' => ConnectionStatus::Active]);
    }

    public function config(Connection $connection): array
    {
        $json = $this->secretBox->open($connection->config_encrypted, $connection->secretContext());
        $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        $config = [];

        if (is_array($decoded)) {
            foreach ($decoded as $key => $value) {
                $config[(string) $key] = $value;
            }
        }

        return $config;
    }
}
