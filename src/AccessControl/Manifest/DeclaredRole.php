<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

/**
 * A role an app declares — a stable `key` (slug), a display `name`, and the set of
 * permission keys it grants. The app owns what the role means; Cbox ID only assigns
 * it to people and stamps it into their token.
 */
final readonly class DeclaredRole
{
    /**
     * @param  list<string>  $permissions  Permission keys this role grants.
     */
    public function __construct(
        public string $key,
        public string $name,
        public ?string $description,
        public array $permissions,
    ) {}
}
