<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\ValueObjects;

/**
 * Who a flag is on (or off) for, beyond its default: named users, named organizations,
 * and a percentage of everyone else.
 *
 * A user or organization rule carries its own value, so a rule can switch a flag OFF for
 * one customer as well as on — which is what makes the precedence (user, then
 * organization, then rollout, then default) mean something. `rolloutPercentage` is
 * 0–100, or null for no rollout: a subject whose stable bucket falls below it gets the
 * flag; everyone else falls through to the default.
 *
 * Saving targeting REPLACES the flag's whole rule set; there is no partial merge, so what
 * a caller sends is exactly what applies.
 */
final readonly class FlagTargeting
{
    /**
     * @param  array<string, bool>  $users  user id => on/off
     * @param  array<string, bool>  $organizations  organization id => on/off
     */
    public function __construct(
        public array $users = [],
        public array $organizations = [],
        public ?int $rolloutPercentage = null,
    ) {}

    public static function none(): self
    {
        return new self;
    }

    /**
     * On for exactly these organizations — the common "beta customers" shape.
     *
     * @param  list<string>  $organizationIds
     */
    public static function organizations(array $organizationIds): self
    {
        return new self(organizations: array_fill_keys($organizationIds, true));
    }

    /**
     * On for exactly these users.
     *
     * @param  list<string>  $userIds
     */
    public static function users(array $userIds): self
    {
        return new self(users: array_fill_keys($userIds, true));
    }

    public static function rollout(int $percentage): self
    {
        return new self(rolloutPercentage: $percentage);
    }

    /** How many user and organization rules this targeting holds. */
    public function ruleCount(): int
    {
        return count($this->users) + count($this->organizations);
    }
}
