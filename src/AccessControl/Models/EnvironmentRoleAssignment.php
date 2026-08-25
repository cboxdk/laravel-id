<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\RoleService;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A user's assignment to a role EVERYWHERE in an environment, rather than inside one
 * organization.
 *
 * The sibling of {@see RoleAssignment}, deliberately not a nullable column on it: "holds
 * Editor in Acme" and "holds Support everywhere" are revoked differently, reviewed
 * differently, and one of them is a much larger thing to grant. See the migration for why
 * a NULL organization also breaks the unique index on every engine.
 *
 * Only a role that is itself environment-wide (`organization_id` null) may be granted
 * this way — {@see RoleService::assignEverywhere()} enforces it.
 * Granting one tenant's role across the whole environment would hand every other tenant a
 * role defined by, and named for, somebody else.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $user_id
 * @property string $role_id
 * @property GrantSource $source
 * @property string|null $source_ref
 */
class EnvironmentRoleAssignment extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'environment_role_assignments';

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
