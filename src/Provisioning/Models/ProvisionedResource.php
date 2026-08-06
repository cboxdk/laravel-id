<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Provisioning\Enums\ResourceState;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The durable mapping of one platform user (on one connection) to the REMOTE
 * SCIM resource it was created as. This statefulness is exactly what separates
 * SCIM provisioning from fire-and-forget webhooks:
 *
 *  - `external_id` is the platform user id we send as SCIM `externalId` — the
 *    stable handle to reconcile a duplicate (409-on-create) back to us;
 *  - `remote_id` is the id the downstream app assigned (SCIM `id`) — captured on
 *    create so every later update PATCHes `/Users/{remote_id}` instead of
 *    re-creating the user;
 *  - `state` / `last_synced_at` record what we last pushed, so a reconcile is a
 *    no-op when nothing changed.
 *
 * Environment-owned, and unique per (environment, connection, user): a user has
 * at most one mirror per downstream app.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $connection_id
 * @property string $user_id
 * @property string $external_id
 * @property string|null $remote_id
 * @property ResourceState $state
 * @property Carbon|null $last_synced_at
 */
class ProvisionedResource extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'provisioned_resources';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'state' => ResourceState::class,
            'last_synced_at' => 'datetime',
        ];
    }
}
