<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Manifest;

/**
 * The outcome of syncing an app manifest — what changed, so callers (and the audit
 * trail) can report it. `unchanged` is true when the manifest checksum matched the
 * last sync and nothing was touched.
 */
final readonly class ManifestSyncResult
{
    /**
     * @param  list<string>  $orphanedRoleKeys  Roles previously declared, now dropped — kept + flagged, not deleted.
     * @param  list<string>  $orphanedPermissionKeys
     */
    public function __construct(
        public bool $unchanged,
        public int $permissionsDeclared,
        public int $rolesDeclared,
        public array $orphanedRoleKeys,
        public array $orphanedPermissionKeys,
    ) {}

    public static function unchanged(): self
    {
        return new self(true, 0, 0, [], []);
    }
}
