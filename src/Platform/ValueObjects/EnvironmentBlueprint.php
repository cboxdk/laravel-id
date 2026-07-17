<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

/**
 * The input to self-serve environment provisioning: the new IdP's name, its first
 * owner (who becomes admin of the new realm), and their first organization. `domain`
 * is an optional custom domain; null routes the environment by its slug subdomain.
 */
final readonly class EnvironmentBlueprint
{
    public function __construct(
        public string $name,
        public string $ownerEmail,
        public ?string $ownerName,
        public string $ownerPassword,
        public string $organizationName,
        public ?string $domain = null,
    ) {}
}
