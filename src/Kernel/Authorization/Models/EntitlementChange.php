<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Models;

use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Append-only history of entitlement changes, for audit and reconciliation.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $key
 * @property array<string, mixed>|null $value
 * @property EntitlementSource $source
 * @property string|null $source_ref
 * @property int $version
 * @property string $change
 * @property Carbon $recorded_at
 */
final class EntitlementChange extends Model implements TenantOwned
{
    use BelongsToTenant;
    use HasUlids;

    public $timestamps = false;

    protected $table = 'entitlement_history';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'value' => 'array',
            'source' => EntitlementSource::class,
            'version' => 'integer',
            'recorded_at' => 'datetime',
        ];
    }
}
