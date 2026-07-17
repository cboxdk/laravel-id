<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A permission — a `feature:action` key. `client_id` null = an org/system-level
 * permission; a non-null `client_id` marks one an app declared through its manifest.
 * `orphaned_at` is set when the declaring app stops declaring it (kept, not deleted).
 *
 * @property string $id
 * @property string|null $client_id
 * @property string $name
 * @property string|null $description
 * @property bool $tenant_assignable
 * @property Carbon|null $orphaned_at
 */
final class Permission extends Model
{
    use HasUlids;

    protected $table = 'permissions';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'tenant_assignable' => 'boolean',
            'orphaned_at' => 'datetime',
        ];
    }
}
