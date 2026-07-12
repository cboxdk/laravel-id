<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\Connection;

interface Connections
{
    /**
     * @param  array<string, mixed>  $config  IdP config (sealed at rest)
     * @param  array<string, mixed>  $mappings  attribute → user-field mappings
     */
    public function create(
        string $organizationId,
        ConnectionType $type,
        string $name,
        array $config,
        array $mappings = [],
    ): Connection;

    public function byId(string $id): ?Connection;

    /**
     * The active connection for an organization, if any.
     */
    public function forOrganization(string $organizationId): ?Connection;

    public function activate(string $id): void;

    /**
     * The decrypted IdP config for a connection.
     *
     * @return array<string, mixed>
     */
    public function config(Connection $connection): array;
}
