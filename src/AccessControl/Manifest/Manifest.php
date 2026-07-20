<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

/**
 * An app's authorization manifest: the roles and permissions it declares. This is
 * the transport-agnostic contract — whether it arrived by SDK push, a pulled
 * `/.well-known/cbox-authz` document, a management-API POST, or manual console
 * entry, it lands here as a {@see Manifest} and is synced identically.
 */
readonly class Manifest
{
    /**
     * @param  list<DeclaredPermission>  $permissions
     * @param  list<DeclaredRole>  $roles
     */
    public function __construct(
        public string $version,
        public array $permissions,
        public array $roles,
    ) {}

    /**
     * A stable content checksum. Re-syncing a manifest whose checksum is unchanged
     * is a no-op, so pull/push/SDK can call `sync` freely without churn.
     */
    public function checksum(): string
    {
        $canonical = [
            'permissions' => array_map(
                static fn (DeclaredPermission $p): array => ['key' => $p->key, 'description' => $p->description],
                $this->sortedPermissions(),
            ),
            'roles' => array_map(
                fn (DeclaredRole $r): array => [
                    'key' => $r->key,
                    'name' => $r->name,
                    'description' => $r->description,
                    'permissions' => $this->sortedStrings($r->permissions),
                ],
                $this->sortedRoles(),
            ),
        ];

        return hash('sha256', (string) json_encode($canonical));
    }

    /**
     * @return list<string>
     */
    public function permissionKeys(): array
    {
        return array_map(static fn (DeclaredPermission $p): string => $p->key, $this->permissions);
    }

    /**
     * @return list<string>
     */
    public function roleKeys(): array
    {
        return array_map(static fn (DeclaredRole $r): string => $r->key, $this->roles);
    }

    /**
     * @return list<DeclaredPermission>
     */
    private function sortedPermissions(): array
    {
        $permissions = $this->permissions;
        usort($permissions, static fn (DeclaredPermission $a, DeclaredPermission $b): int => strcmp($a->key, $b->key));

        return $permissions;
    }

    /**
     * @return list<DeclaredRole>
     */
    private function sortedRoles(): array
    {
        $roles = $this->roles;
        usort($roles, static fn (DeclaredRole $a, DeclaredRole $b): int => strcmp($a->key, $b->key));

        return $roles;
    }

    /**
     * @param  list<string>  $values
     * @return list<string>
     */
    private function sortedStrings(array $values): array
    {
        sort($values);

        return $values;
    }
}
