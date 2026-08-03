<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionStatus;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\ValueObjects\OAuth2ConnectionConfig;
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
        ?string $provider = null,
    ): Connection {
        if ($provider !== null && ProviderCatalog::find($provider) === null) {
            // Refused rather than stored. A connection labelled with a key the catalogue
            // does not have would render a sign-in button nobody can complete, and the
            // failure would land on the person clicking it rather than on whoever typed
            // it — hours later, with no way to tell the two apart.
            throw InvalidAssertion::make('unknown provider: '.$provider);
        }

        $connection = new Connection;
        $connection->id = (string) Str::ulid();
        $connection->fill([
            'organization_id' => $organizationId,
            'type' => $type,
            'name' => $name,
            'status' => ConnectionStatus::Draft,
            'mappings' => $mappings,
            'provider' => $provider,
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
            // Catalogue providers are offered as buttons, not as the way an organization
            // signs in. Without this clause, enabling Google could become an
            // organization's enterprise SSO purely by being the first active row back.
            ->whereNull('provider')
            ->first();
    }

    public function catalogueProvidersFor(string $organizationId): array
    {
        return array_values(
            Connection::query()
                ->where('organization_id', $organizationId)
                ->where('status', ConnectionStatus::Active->value)
                ->whereNotNull('provider')
                // Ordered by the column rather than by insertion, so the buttons do not
                // rearrange themselves between page loads or between replicas.
                ->orderBy('provider')
                ->get()
                ->all()
        );
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

    public function oauth2Config(Connection $connection): OAuth2ConnectionConfig
    {
        $this->assertType($connection, ConnectionType::OAuth2);

        // fromArray() refuses a config naming an OIDC provider, so a connection stored
        // with the wrong protocol cannot be driven down this path — where no id_token
        // would ever be verified.
        return OAuth2ConnectionConfig::fromArray($this->config($connection));
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
