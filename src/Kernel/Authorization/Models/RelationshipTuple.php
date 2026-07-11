<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Models;

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
final class RelationshipTuple extends Model
{
    use HasUlids;

    protected $table = 'relationship_tuples';

    protected $guarded = [];
}
