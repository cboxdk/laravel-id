<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Models\Client;

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
    ) {}

    public static function of(Client $client): self
    {
        $environmentId = $client->getAttribute('environment_id');

        return new self(
            is_string($environmentId) && $environmentId !== '' ? $environmentId : null,
            $client->organization_id,
            $client->isDynamicallyRegistered(),
        );
    }

    /**
     * Created by the environment's operators — not by a tenant, and not by itself.
     */
    public function isEnvironmentOwned(): bool
    {
        return $this->organizationId === null && ! $this->dynamicallyRegistered;
    }
}
