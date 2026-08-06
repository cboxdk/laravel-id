<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Manifest\Manifest;
use Cbox\Id\AccessControl\Manifest\ManifestSyncResult;
use Cbox\Id\AccessControl\Models\AppManifest;
use Cbox\Id\AccessControl\Models\Role;

/**
 * Ingests an app's declared roles/permissions ({@see Manifest}) into Cbox ID. The
 * transport is the caller's business — SDK push, a pulled well-known document, a
 * management-API POST, or manual console entry all resolve to a {@see Manifest} and
 * call {@see self::sync()}.
 */
interface AppManifests
{
    /**
     * Idempotently reconcile an app's declared catalog to match the manifest:
     * upsert its permissions + roles (scoped to the app), (re)link each role to its
     * permissions, and flag anything the app no longer declares as orphaned WITHOUT
     * deleting it — a live role assignment is never silently revoked. A manifest
     * whose checksum is unchanged since the last sync is a no-op.
     */
    public function sync(string $clientId, Manifest $manifest): ManifestSyncResult;

    /**
     * The last-synced manifest record for an app, or null if it never declared one.
     */
    public function current(string $clientId): ?AppManifest;

    /**
     * The roles an app currently declares (excludes orphaned), for the assignment
     * picker and the group→role mapping UI.
     *
     * @return list<Role>
     */
    public function declaredRoles(string $clientId): array;
}
