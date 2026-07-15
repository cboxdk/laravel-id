<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Provisioning\Enums\OperationStatus;
use Cbox\Id\Provisioning\Enums\OperationType;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A durable outbox row: one pending SCIM operation for one user on one
 * connection. A thin request-thread listener only ENQUEUES these (never
 * delivers); a queued per-connection drain works them off with bounded backoff,
 * a dead-letter cap and a circuit breaker.
 *
 * `payload` snapshots the subject attributes at enqueue time, so the operation is
 * self-contained and delivers correctly even if the user changes again before the
 * drain runs. Environment-owned, so the drain — which reconstructs the
 * connection's environment in a worker — only ever loads this environment's rows.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $connection_id
 * @property string $user_id
 * @property OperationType $type
 * @property array<string, mixed> $payload
 * @property OperationStatus $status
 * @property int $attempt
 * @property int|null $response_code
 * @property Carbon|null $next_attempt_at
 * @property Carbon|null $delivered_at
 * @property string|null $last_error
 */
class ProvisioningOperation extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'provisioning_operations';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => OperationType::class,
            'payload' => 'array',
            'status' => OperationStatus::class,
            'attempt' => 'integer',
            'response_code' => 'integer',
            'next_attempt_at' => 'datetime',
            'delivered_at' => 'datetime',
        ];
    }
}
