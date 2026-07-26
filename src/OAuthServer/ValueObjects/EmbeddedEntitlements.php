<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The Claims-mode entitlements baked into an access token, with the highest
 * version among them — the staleness signal a resource server compares against
 * when it wants to know whether its stateless decision is still current.
 *
 * `values` stays an array because it is written straight into the JWT `ent` claim:
 * that is a serialization boundary, and the shape is the tenant's own entitlement
 * payload, not a fixed domain structure.
 */
readonly class EmbeddedEntitlements
{
    /**
     * @param  array<string, array<string, mixed>>  $values
     */
    public function __construct(
        public array $values,
        public int $version,
    ) {}

    public static function none(): self
    {
        return new self([], 0);
    }

    public function isEmpty(): bool
    {
        return $this->values === [];
    }
}
