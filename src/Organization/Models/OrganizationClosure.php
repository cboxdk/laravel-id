<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Transitive closure of the organization tree: one row per (ancestor, descendant)
 * pair, including each node's self-row at depth 0. Enables O(1) ancestor/descendant
 * and transitive-access lookups at arbitrary depth.
 *
 * @property string $id
 * @property string $ancestor_id
 * @property string $descendant_id
 * @property int $depth
 */
class OrganizationClosure extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    public $timestamps = false;

    protected $table = 'organization_closure';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'depth' => 'integer',
        ];
    }
}
