<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\AccessControl\Enums\RoleSource;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A role. `organization_id` null = a system role reusable across orgs within the
 * owning environment. A non-null `client_id` marks an APP-DECLARED role (from that
 * app's manifest, `source = manifest`) — keyed by its stable `key` slug and
 * read-only in the console. `orphaned_at` is set when the declaring app drops the
 * role from a later manifest; the row (and any assignments) are kept, not deleted.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string|null $client_id
 * @property string $name
 * @property string|null $key
 * @property string|null $description
 * @property RoleSource $source
 * @property Carbon|null $orphaned_at
 */
final class Role extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'roles';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'source' => RoleSource::class,
            'orphaned_at' => 'datetime',
        ];
    }
}
