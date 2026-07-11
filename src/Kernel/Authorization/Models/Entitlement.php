<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Models;

use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Current projected entitlement state for an org (the source of truth is external).
 *
 * @property string $id
 * @property string $organization_id
 * @property string $key
 * @property array<string, mixed> $value
 * @property EnforcementMode $mode
 * @property EntitlementSource $source
 * @property string|null $source_ref
 * @property int $version
 * @property Carbon|null $effective_at
 * @property Carbon|null $expires_at
 */
final class Entitlement extends Model
{
    use HasUlids;

    protected $table = 'entitlements';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'value' => 'array',
            'mode' => EnforcementMode::class,
            'source' => EntitlementSource::class,
            'version' => 'integer',
            'effective_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
