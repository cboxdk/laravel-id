<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

use Cbox\Id\Migration\ValueObjects\LegacyLoginDeclaration;

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
        /**
         * Where this app's OLD login lives, when it is migrating off one.
         *
         * A proposal, not an instruction — see {@see LegacyLoginDeclaration}. It rides
         * the manifest because it is the same kind of fact as a role: something the app
         * knows about itself, versioned with the deploy, rather than a URL somebody
         * pastes into a console and a secret somebody pastes into an env file.
         */
        public ?LegacyLoginDeclaration $legacyLogin = null,
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
                ] + $this->staffMarker($r),
                $this->sortedRoles(),
            ),
        ];

        return hash('sha256', (string) json_encode($canonical));
    }

    /**
     * A staff-only role's marker in the canonical form — present ONLY when the role is
     * staff-only.
     *
     * It has to be in the checksum at all, because an unchanged checksum skips the sync:
     * an app that marks its "Support" role staff-only in a new deploy would otherwise
     * keep it assignable by every tenant, silently, for as long as nothing else in the
     * manifest changed.
     *
     * And it is present only when FALSE because the canonical form is a cross-SDK
     * contract (tests/Fixtures/AccessControl/manifest_hash.json, asserted by id-js,
     * id-python and id-go too). Every manifest that declares no staff role — every
     * manifest that exists today — hashes to exactly the bytes it always has, so no
     * SDK's checksum drifts and no app re-syncs for nothing.
     *
     * @return array{tenant_assignable?: false}
     */
    private function staffMarker(DeclaredRole $role): array
    {
        return $role->tenantAssignable ? [] : ['tenant_assignable' => false];
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
