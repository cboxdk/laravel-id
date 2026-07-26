<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\ValueObjects\OidcConnectionConfig;
use Cbox\Id\Federation\ValueObjects\SamlConnectionConfig;

interface Connections
{
    /**
     * Create a DRAFT connection. The config is the raw map that gets sealed — an
     * array here on purpose: this is the JSON-persistence boundary, and a draft is
     * allowed to be incomplete (an admin saves what they have, imports the rest from
     * IdP metadata or OIDC discovery, then activates). Completeness is asserted when
     * the config is READ, by {@see samlConfig()} / {@see oidcConfig()}.
     *
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

    public function activate(string $organizationId, string $id): void;

    /**
     * The connection's SAML configuration, unsealed and parsed.
     *
     * Typed, not a string-keyed map: this is durable admin-authored configuration
     * that four separate subsystems read (assertion validation, SP metadata,
     * SP-initiated login, Single Logout), and threading it as an array meant each of
     * them re-read the same string keys and re-validated the same shape.
     *
     * @throws InvalidAssertion when the connection is not SAML, or its config is
     *                          missing a required field
     */
    public function samlConfig(Connection $connection): SamlConnectionConfig;

    /**
     * The connection's OIDC configuration, unsealed and parsed.
     *
     * @throws InvalidAssertion when the connection is not OIDC, or its config is
     *                          missing a required field
     */
    public function oidcConfig(Connection $connection): OidcConnectionConfig;

    /**
     * The decrypted config as it is stored — the unseal half of the persistence
     * boundary, for round-tripping and for admin surfaces that edit the raw map.
     * Prefer {@see samlConfig()} / {@see oidcConfig()} anywhere the config is USED.
     *
     * @return array<string, mixed>
     */
    public function config(Connection $connection): array;
}
