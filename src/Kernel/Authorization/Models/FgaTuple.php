<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Models;

use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\SubjectRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One stored fine-grained tuple. Environment-owned and NOT organization-owned: the model
 * is the environment's, and an organization is whatever resource the schema calls one.
 *
 * `subject_relation` is '' — never null — for a direct subject, so the unique index
 * really is unique on every engine (NULLs compare distinct in a unique index, so a
 * nullable column would let the same direct grant be stored twice).
 *
 * @property string $id
 * @property string $environment_id
 * @property string $resource_type
 * @property string $resource_id
 * @property string $relation
 * @property string $subject_type
 * @property string $subject_id
 * @property string $subject_relation
 * @property int $created_revision
 * @property Carbon $created_at
 */
class FgaTuple extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    public const null UPDATED_AT = null;

    protected $table = 'fga_tuples';

    protected $guarded = [];

    public function toTuple(): Tuple
    {
        return new Tuple(
            ResourceRef::of($this->resource_type, $this->resource_id),
            $this->relation,
            SubjectRef::of($this->subject_type, $this->subject_id, $this->subject_relation),
        );
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['created_revision' => 'integer'];
    }
}
