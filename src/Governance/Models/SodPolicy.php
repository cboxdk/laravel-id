<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A Segregation-of-Duties policy: a set of roles that must not be held together.
 * Holding two or more roles from `role_ids` at the same time is a violation (the
 * classic "raise a purchase order" + "approve payment" toxic combination).
 *
 * `organization_id` null = an environment-wide policy that applies in every org.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string $name
 * @property string|null $description
 * @property bool $active
 * @property array<int, string> $role_ids
 */
final class SodPolicy extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'governance_sod_policies';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'active' => 'boolean',
            'role_ids' => 'array',
        ];
    }
}
