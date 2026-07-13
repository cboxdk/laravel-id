<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A role. `organization_id` null = a system role reusable across orgs within the
 * owning environment.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string $name
 * @property string|null $description
 */
final class Role extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'roles';

    protected $guarded = [];
}
