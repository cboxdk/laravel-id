<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $organization_id
 * @property string $object_type
 * @property string $object_id
 * @property string $relation
 * @property string $subject_type
 * @property string $subject_id
 * @property string|null $subject_relation
 */
final class RelationshipTuple extends Model implements TenantOwned
{
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'relationship_tuples';

    protected $guarded = [];
}
