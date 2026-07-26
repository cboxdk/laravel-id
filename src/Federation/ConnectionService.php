<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionStatus;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\ValueObjects\OidcConnectionConfig;
use Cbox\Id\Federation\ValueObjects\SamlConnectionConfig;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Illuminate\Support\Str;

class ConnectionService implements Connections
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

    public function activate(string $organizationId, string $id): void
    {
        // Scope to the owning org so an admin can't flip another tenant's draft.
        Connection::query()
            ->whereKey($id)
            ->where('organization_id', $organizationId)
            ->first()?->update(['status' => ConnectionStatus::Active]);
    }

    public function samlConfig(Connection $connection): SamlConnectionConfig
    {
        $this->assertType($connection, ConnectionType::Saml);

        return SamlConnectionConfig::fromArray($this->config($connection));
    }

    public function oidcConfig(Connection $connection): OidcConnectionConfig
    {
        $this->assertType($connection, ConnectionType::Oidc);

        return OidcConnectionConfig::fromArray($this->config($connection));
    }

    /**
     * Reading a connection's config as the WRONG protocol is a programming error that
     * would otherwise surface as a confusing "missing [idp_entity_id]" on an OIDC
     * connection. Name it.
     */
    private function assertType(Connection $connection, ConnectionType $expected): void
    {
        if ($connection->type !== $expected) {
            throw InvalidAssertion::make(
                "connection [{$connection->id}] is {$connection->type->value}, not {$expected->value}"
            );
        }
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
