<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A user's assignment to a role within an organization.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $user_id
 * @property string $role_id
 * @property GrantSource $source
 * @property string|null $source_ref
 */
final class RoleAssignment extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'role_assignments';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'source' => GrantSource::class,
        ];
    }
}
