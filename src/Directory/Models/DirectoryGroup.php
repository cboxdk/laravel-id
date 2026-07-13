<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * A SCIM Group (RFC 7643 §4.2) synced from the customer's directory. Membership is
 * the set of {@see DirectoryUser}s in this directory, so a group maps cleanly onto
 * role/entitlement provisioning downstream.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $directory_id
 * @property string|null $external_id
 * @property string $display_name
 */
final class DirectoryGroup extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'directory_groups';

    protected $guarded = [];

    /**
     * @return BelongsToMany<DirectoryUser, $this>
     */
    public function members(): BelongsToMany
    {
        return $this->belongsToMany(
            DirectoryUser::class,
            'directory_group_members',
            'group_id',
            'directory_user_id',
        )->withTimestamps();
    }
}
