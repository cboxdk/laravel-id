<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

/**
 * A role an app declares — a stable `key` (slug), a display `name`, and the set of
 * permission keys it grants. The app owns what the role means; Cbox ID only assigns
 * it to people and stamps it into their token.
 *
 * `tenantAssignable` (default true) is false for a STAFF role: one the app's vendor
 * grants to its own support people and administrators, typically across every customer
 * with `Roles::assignEverywhere()`. A tenant administrator is never offered it and cannot
 * grant it by naming its id. The default is the permissive one, unlike a declared
 * permission's, because an app role that tenants cannot hand out is the exception — a
 * customer assigning the app's "Editor" to their own people is the whole point of
 * declaring it.
 */
readonly class DeclaredRole
{
    /**
     * @param  list<string>  $permissions  Permission keys this role grants.
     */
    public function __construct(
        public string $key,
        public string $name,
        public ?string $description,
        public array $permissions,
        public bool $tenantAssignable = true,
    ) {}
}
