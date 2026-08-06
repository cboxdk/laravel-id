<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Webhooks\Enums\EndpointStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A subscriber endpoint. `organization_id` null = a platform-wide endpoint —
 * platform-wide is scoped to ONE environment (the model is environment-owned),
 * so a null-org endpoint never receives another environment's events. The
 * signing secret is stored sealed (Crypto SecretBox) and only opened at delivery
 * time to compute the HMAC signature.
 *
 * `status` is the operator's INTENT (active/paused, changed only by hand). The
 * `consecutive_failures` / `circuit_opened_at` / `last_success_at` / `last_error`
 * columns are transient HEALTH, driven by
 * \Cbox\Id\Webhooks\Support\EndpointCircuitBreaker and self-healing after the
 * cooldown — see that class for why the two are kept apart.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string $url
 * @property string $secret_encrypted
 * @property array<int, string> $event_types
 * @property int $last_sequence
 * @property EndpointStatus $status
 * @property int $consecutive_failures
 * @property Carbon|null $circuit_opened_at
 * @property Carbon|null $last_success_at
 * @property string|null $last_error
 */
class WebhookEndpoint extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'webhook_endpoints';

    protected $guarded = [];

    public function secretContext(): string
    {
        return 'cbox-id:webhook-endpoint:'.$this->id;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'event_types' => 'array',
            'last_sequence' => 'integer',
            'status' => EndpointStatus::class,
            'consecutive_failures' => 'integer',
            'circuit_opened_at' => 'datetime',
            'last_success_at' => 'datetime',
        ];
    }
}
