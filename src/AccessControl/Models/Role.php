<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A role. `organization_id` null = a system role reusable across orgs.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $name
 * @property string|null $description
 */
final class Role extends Model
{
    use HasUlids;

    protected $table = 'roles';

    protected $guarded = [];
}
