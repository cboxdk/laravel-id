<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A "directory group → role" mapping: everyone in `group_id` gets `role_id` (via the
 * `pushed` grant source) within `organization_id`. `priority` orders overlapping
 * mappings.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $group_id
 * @property string $role_id
 * @property int $priority
 */
class GroupRoleMapping extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'group_role_mappings';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'priority' => 'integer',
        ];
    }
}
