<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Contracts;

use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\Provisioning\ValueObjects\ScimResult;

/**
 * The OUTBOUND SCIM 2.0 HTTP client — the mirror of the platform's inbound SCIM
 * server. Every operation is SSRF-guarded (resolve-once pin, no redirects,
 * TLS-verify on) and authenticated from the connection's sealed secret.
 *
 * Implementations MUST NOT leak the bearer/OAuth secret into any returned
 * {@see ScimResult} or thrown exception.
 */
interface ScimClient
{
    /**
     * POST /Users — create the resource. On 201 the {@see ScimResult} carries the
     * remote `id`; on 409 the caller reconciles via {@see findByExternalId()}.
     *
     * @param  array<string, mixed>  $resource  a SCIM `User` resource body
     */
    public function createUser(ProvisioningConnection $connection, array $resource): ScimResult;

    /**
     * PATCH /Users/{id} with a `PatchOp` body — update changed attributes,
     * deactivate (`active` = false) or reactivate. A 404 means the remote record
     * is gone and the caller should recreate.
     *
     * @param  list<array{op: string, path?: string, value?: mixed}>  $operations
     */
    public function patchUser(ProvisioningConnection $connection, string $remoteId, array $operations): ScimResult;

    /** DELETE /Users/{id} — hard de-provision (per the connection's policy). */
    public function deleteUser(ProvisioningConnection $connection, string $remoteId): ScimResult;

    /**
     * GET /Users?filter=externalId eq "…" — locate a remote record already
     * created for this platform user, to reconcile a create conflict (409) back
     * to it instead of duplicating. Returns the remote id, or null if none.
     */
    public function findByExternalId(ProvisioningConnection $connection, string $externalId): ?string;
}
