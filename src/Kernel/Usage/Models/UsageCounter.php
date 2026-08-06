<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * One per-day usage counter for a `(environment, organization, metric, period)` tuple.
 *
 * `organization_id` is stored as `''` for a system-scoped (org-less) count rather than
 * NULL — SQLite and Postgres treat NULLs as distinct in a unique index, which would
 * let duplicate org-less rows accumulate and break the counter. Env-scoped via
 * {@see BelongsToEnvironment}; the org is a plainly-managed column (metering records
 * for an explicit org and queries across orgs, so it is NOT tenant-scoped).
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $metric
 * @property string $period
 * @property int $count
 */
class UsageCounter extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'usage_counters';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'count' => 'integer',
        ];
    }
}
