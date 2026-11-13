<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\SelfRegisteredScopes;

/**
 * The facts about a client that decide which registered scopes it may hold: the
 * environment it lives in, the organization that owns it, and whether it registered
 * itself.
 *
 * A DYNAMICALLY REGISTERED CLIENT IS NOT ENVIRONMENT-OWNED, whatever its row says.
 * RFC 7591 registration writes `organization_id = null` — the same value an operator's
 * own console client carries — but the registrant is whoever reached `/oauth/register`,
 * which in `open` mode is anyone. Reading null as "the environment trusts this" would
 * hand every self-registered client every scope the environment owns.
 */
readonly class ScopeHolder
{
    public function __construct(
        public ?string $environmentId,
        public ?string $organizationId = null,
        public bool $dynamicallyRegistered = false,
        public bool $resourceBound = false,
    ) {}

    public static function of(Client $client): self
    {
        $environmentId = $client->getAttribute('environment_id');

        return new self(
            is_string($environmentId) && $environmentId !== '' ? $environmentId : null,
            $client->organization_id,
            $client->isDynamicallyRegistered(),
            self::isResourceBound($client),
        );
    }

    /**
     * Registered ITSELF for the host's declared resources — in `mcp` mode, or as a client
     * ID metadata document client — and so never the holder of a registered API's scope
     * ({@see SelfRegisteredScopes}). A self-registered row from before the profile was
     * recorded is judged by the mode the server is in now.
     */
    private static function isResourceBound(Client $client): bool
    {
        if ($client->isMetadataDocumentClient()) {
            return true;
        }

        if (! $client->isDynamicallyRegistered()) {
            return false;
        }

        $profile = $client->registration_profile;

        return is_string($profile) && $profile !== ''
            ? $profile === 'mcp'
            : config('cbox-id.oauth.dynamic_registration.mode') === 'mcp';
    }

    /**
     * Created by the environment's operators — not by a tenant, and not by itself.
     */
    public function isEnvironmentOwned(): bool
    {
        return $this->organizationId === null && ! $this->dynamicallyRegistered;
    }
}
