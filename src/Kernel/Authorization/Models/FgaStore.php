<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An environment's fine-grained authorization model, one row per environment: the schema
 * (as written, and parsed) and the REVISION — the monotonic counter every write to the
 * model advances, which consistency tokens name and cached answers are keyed by.
 *
 * `revision_tag` is a random value replaced with every advance. It goes into cache keys
 * next to the revision so that an answer computed inside a transaction that then rolled
 * back — cached under a revision number some LATER write will commit with different
 * tuples — can never be found again: the later write commits a different tag.
 *
 * @property string $id
 * @property string $environment_id
 * @property int $revision
 * @property string $revision_tag
 * @property string|null $schema_source
 * @property string|null $schema
 * @property string|null $schema_hash
 * @property int $schema_version
 * @property Carbon|null $schema_updated_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class FgaStore extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'fga_stores';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'revision' => 'integer',
            'schema_version' => 'integer',
            'schema_updated_at' => 'datetime',
        ];
    }
}
