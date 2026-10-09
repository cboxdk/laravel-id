<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Models;

use Cbox\Id\FeatureFlags\Enums\TargetType;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Cache;

/**
 * One targeting rule: this flag is `enabled` (on or off) for this user or organization.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $feature_flag_id
 * @property TargetType $target_type
 * @property string $target_id
 * @property bool $enabled
 */
class FeatureFlagTarget extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'feature_flag_targets';

    protected $guarded = [];

    protected static function booted(): void
    {
        $forget = static function (self $target): void {
            Cache::forget(FeatureFlag::cacheKey($target->environment_id));
        };

        static::saved($forget);
        static::deleted($forget);
    }

    /**
     * @return BelongsTo<FeatureFlag, $this>
     */
    public function flag(): BelongsTo
    {
        return $this->belongsTo(FeatureFlag::class, 'feature_flag_id');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'target_type' => TargetType::class,
            'enabled' => 'boolean',
        ];
    }
}
