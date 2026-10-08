<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Models;

use Cbox\Id\Directory\Support\DirectoryRevision;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Carbon;

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
 * @property int $version
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class DirectoryGroup extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'directory_groups';

    protected $guarded = [];

    /**
     * Record a change the row itself does not show — a membership edit lands in the
     * pivot, never on this row — as a new revision, so the group's entity-tag and
     * `meta.lastModified` move with it (RFC 7644 §3.14).
     */
    public function recordRevision(): void
    {
        $this->forceFill(['version' => $this->version + 1])->save();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['version' => 'integer'];
    }

    protected static function booted(): void
    {
        static::saving(static function (self $model): void {
            DirectoryRevision::advance($model);
        });
    }

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
