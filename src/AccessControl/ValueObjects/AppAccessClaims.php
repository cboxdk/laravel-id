<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\ValueObjects;

/**
 * A user's effective access as it should appear in a token minted FOR a specific
 * app — the role keys they hold that are relevant to that app (its own declared
 * roles plus org-wide roles) and the union of those roles' permission keys. Other
 * apps' roles are deliberately excluded, so an app only ever sees access it owns.
 */
final readonly class AppAccessClaims
{
    /**
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     */
    public function __construct(
        public array $roles,
        public array $permissions,
    ) {}

    public function isEmpty(): bool
    {
        return $this->roles === [] && $this->permissions === [];
    }
}
