<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Models;

use Cbox\Id\ExternalActions\Enums\ActionEndpointStatus;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

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
final class ExternalActionEndpoint extends Model implements EnvironmentOwned
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
