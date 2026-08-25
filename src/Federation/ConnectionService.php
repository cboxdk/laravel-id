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
use Cbox\Id\Kernel\Runtime\RequestLifetime;
use Illuminate\Support\Str;

class ConnectionService implements Connections
{
    /**
     * The enterprise connection per organization, for the request in flight.
     *
     * ASKED FIVE TIMES PER DASHBOARD RENDER, measured: the page asks, the setup checklist
     * asks the identical question again, the connectors overview asks a third time, and
     * Volt runs `with()` twice. It is one row, it cannot change mid-request, and the answer
     * decides how an organization signs in.
     *
     * Keyed on the request lifetime as well as the organization, like every other memo in
     * this package: this service is a singleton, and a memo that outlived the request would
     * hand a queue worker the first job's connection for the life of the process — the
     * failure {@see RequestLifetime} exists to make impossible.
     *
     * @var array<string, Connection|null>
     */
    private array $memo = [];

    private ?RequestLifetime $memoLifetime = null;

    public function __construct(private readonly SecretBox $secretBox) {}

    public function create(
        ?string $organizationId,
        ConnectionType $type,
        string $name,
        array $config,
        array $mappings = [],
        ?string $provider = null,
    ): Connection {
        // Same reason as `activate()`: creating a connection changes which one an
        // organization signs in with. The environment's own connection is memoised under
        // a key of its own — `null` cannot be an array key, and using `''` for it would
        // collide with nothing today and with the first empty-string caller tomorrow.
        unset($this->memo[$this->memoKey($organizationId)]);

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

    public function forOrganization(?string $organizationId): ?Connection
    {
        $lifetime = RequestLifetime::current(app());

        if ($this->memoLifetime !== $lifetime) {
            $this->memo = [];
            $this->memoLifetime = $lifetime;
        }

        $key = $this->memoKey($organizationId);

        if (array_key_exists($key, $this->memo)) {
            return $this->memo[$key];
        }

        return $this->memo[$key] = Connection::query()
            ->when(
                $organizationId === null,
                fn ($query) => $query->whereNull('organization_id'),
                fn ($query) => $query->where('organization_id', $organizationId),
            )
            ->where('status', ConnectionStatus::Active->value)
            // Catalogue providers are offered as buttons, not as the way an organization
            // signs in. Without this clause, enabling Google could become an
            // organization's enterprise SSO purely by being the first active row back.
            ->whereNull('provider')
            ->first();
    }

    public function catalogueProvidersFor(?string $organizationId): array
    {
        return array_values(
            Connection::query()
                ->when(
                    $organizationId === null,
                    fn ($query) => $query->whereNull('organization_id'),
                    fn ($query) => $query->where('organization_id', $organizationId),
                )
                ->where('status', ConnectionStatus::Active->value)
                ->whereNotNull('provider')
                // Ordered by the column rather than by insertion, so the buttons do not
                // rearrange themselves between page loads or between replicas.
                ->orderBy('provider')
                ->get()
                ->all()
        );
    }

    public function activate(?string $organizationId, string $id): void
    {
        // The memo answers "which connection does this organization sign in with", and
        // this is the method that changes it. A memo that survives its own write is the
        // bug memoising introduces.
        unset($this->memo[$this->memoKey($organizationId)]);

        // Scope to the owning org so an admin can't flip another tenant's draft — and
        // null scopes to the environment's own, which is not a wildcard: a caller naming
        // no organization must not be able to activate a tenant's draft either.
        Connection::query()
            ->whereKey($id)
            ->when(
                $organizationId === null,
                fn ($query) => $query->whereNull('organization_id'),
                fn ($query) => $query->where('organization_id', $organizationId),
            )
            ->first()?->update(['status' => ConnectionStatus::Active]);
    }

    /**
     * The memo key for an owner. `null` is not a valid array key and `''` would be
     * indistinguishable from an empty-string organization id, so the environment's own
     * connection gets a key no id can collide with.
     */
    private function memoKey(?string $organizationId): string
    {
        return $organizationId ?? "\0environment";
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
