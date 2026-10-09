<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Models;

use Cbox\Id\FeatureFlags\Enums\TargetType;
use Cbox\Id\FeatureFlags\ValueObjects\FlagRule;
use Cbox\Id\FeatureFlags\ValueObjects\FlagTargeting;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;

/**
 * A feature flag: a named switch an app asks about per user and organization.
 *
 * Environment-owned — a flag defined in staging does not exist in production, and its
 * targeting can name only that environment's users and organizations.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $key
 * @property string|null $description
 * @property bool $enabled
 * @property bool $default_value
 * @property int|null $rollout_percentage
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class FeatureFlag extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'feature_flags';

    protected $guarded = [];

    /**
     * The one cache entry that holds an environment's whole compiled flag set.
     */
    public static function cacheKey(string $environmentKey): string
    {
        return 'cbox-id:feature-flags:'.$environmentKey;
    }

    /**
     * Forget the environment's compiled set whenever a flag changes — at the model, so a
     * new mutation path cannot forget to. Targets do the same ({@see FeatureFlagTarget}).
     */
    protected static function booted(): void
    {
        $forget = static function (self $flag): void {
            Cache::forget(self::cacheKey($flag->environment_id));
        };

        static::saved($forget);
        static::deleted($forget);
    }

    /**
     * @return HasMany<FeatureFlagTarget, $this>
     */
    public function targets(): HasMany
    {
        return $this->hasMany(FeatureFlagTarget::class, 'feature_flag_id');
    }

    /**
     * The flag's rules, read from its (loaded or freshly queried) targets.
     */
    public function targeting(): FlagTargeting
    {
        $users = [];
        $organizations = [];

        foreach ($this->targets as $target) {
            if ($target->target_type === TargetType::User) {
                $users[$target->target_id] = $target->enabled;
            } else {
                $organizations[$target->target_id] = $target->enabled;
            }
        }

        ksort($users);
        ksort($organizations);

        return new FlagTargeting($users, $organizations, $this->rollout_percentage);
    }

    public function rule(): FlagRule
    {
        $targeting = $this->targeting();

        return new FlagRule(
            key: $this->key,
            enabled: $this->enabled,
            defaultValue: $this->default_value,
            rolloutPercentage: $targeting->rolloutPercentage,
            users: $targeting->users,
            organizations: $targeting->organizations,
        );
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'default_value' => 'boolean',
            'rollout_percentage' => 'integer',
        ];
    }
}
