<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\ValueObjects\OAuth2ConnectionConfig;
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
     * @param  string|null  $provider  the catalogue key this came from, or null when an
     *                                 administrator described the provider by hand
     */
    public function create(
        ?string $organizationId,
        ConnectionType $type,
        string $name,
        array $config,
        array $mappings = [],
        ?string $provider = null,
    ): Connection;

    public function byId(string $id): ?Connection;

    /**
     * The organization's ENTERPRISE sign-on connection — the one its people are routed
     * to — or null.
     *
     * Deliberately excludes catalogue-backed providers. A tenant may enable several of
     * those at once, and they are offered as buttons on the sign-in page rather than
     * being the way an organization signs in. Before the distinction existed this
     * returned whichever active row came back first, so enabling Google could silently
     * become an organization's SSO.
     */
    /**
     * The active connection an organization signs in with — or, when `$organizationId` is
     * null, the one the ENVIRONMENT itself owns. An environment that does not use
     * organizations still has people to sign in, and single sign-on is the capability
     * they are most likely to want.
     */
    public function forOrganization(?string $organizationId): ?Connection;

    /**
     * The organization's active catalogue-backed providers, in a stable order.
     *
     * This is what the sign-in page renders as buttons, so it must be cheap: the
     * provider key lives in a column precisely so that answering it does not mean
     * unsealing every connection's config.
     *
     * @return list<Connection>
     */
    public function catalogueProvidersFor(?string $organizationId): array;

    public function activate(?string $organizationId, string $id): void;

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
     * The connection's OAuth 2.0 configuration, unsealed and parsed.
     *
     * @throws InvalidAssertion when the connection is not OAuth 2.0, when its config is
     *                          incomplete, or when it names a provider that speaks OIDC
     *                          — driving one of those through this path would mean no
     *                          id_token was ever verified
     */
    public function oauth2Config(Connection $connection): OAuth2ConnectionConfig;

    /**
     * The decrypted config as it is stored — the unseal half of the persistence
     * boundary, for round-tripping and for admin surfaces that edit the raw map.
     * Prefer {@see samlConfig()} / {@see oidcConfig()} anywhere the config is USED.
     *
     * @return array<string, mixed>
     */
    public function config(Connection $connection): array;
}
