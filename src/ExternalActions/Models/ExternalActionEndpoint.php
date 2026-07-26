<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Models;

use Cbox\Id\ExternalActions\DatabaseExternalActions;
use Cbox\Id\ExternalActions\Enums\ActionEndpointStatus;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;

/**
 * A registered external hook endpoint: a customer HTTPS URL the platform calls
 * synchronously at a {@see HookPoint}. The per-endpoint HMAC signing secret is
 * stored sealed (Crypto SecretBox) and opened only at send time to sign the request.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property HookPoint $hook_point
 * @property string $url
 * @property string $secret_encrypted
 * @property ActionEndpointStatus $status
 */
class ExternalActionEndpoint extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'external_action_endpoints';

    protected $guarded = [];

    public function secretContext(): string
    {
        return 'cbox-id:external-action:'.$this->id;
    }

    /**
     * The cache key for one environment's active endpoints at one hook point — see
     * {@see DatabaseExternalActions::active()} for why the
     * organization is deliberately not part of it.
     */
    public static function cacheKey(string $environmentKey, HookPoint $hookPoint): string
    {
        return 'cbox-id:external-actions:'.$environmentKey.':'.$hookPoint->value;
    }

    /**
     * Invalidate at the model, not at each call site.
     *
     * Registering, pausing, activating and removing an endpoint all change what the
     * pipeline must call, and a stale entry here means either a security hook that
     * silently stops firing or a paused one that keeps firing. The row knows its own
     * environment and hook point, so this is the one place that cannot be forgotten
     * when a new mutation path is added.
     *
     * Only the row's CURRENT (environment, hook point) is forgotten, because that is
     * the only entry it can ever have been in: `hook_point` is assigned once at
     * registration and no path reassigns it — pausing and activating change `status`,
     * removal deletes the row.
     */
    protected static function booted(): void
    {
        $forget = static function (self $endpoint): void {
            Cache::forget(self::cacheKey($endpoint->environment_id, $endpoint->hook_point));
        };

        static::saved($forget);
        static::deleted($forget);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'hook_point' => HookPoint::class,
            'status' => ActionEndpointStatus::class,
        ];
    }
}
