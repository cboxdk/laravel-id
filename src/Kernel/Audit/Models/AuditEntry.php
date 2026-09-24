<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Models;

use Cbox\AuditChain\Models\ChainEntry;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Support\Carbon;

/**
 * A single append-only audit entry. Not tenant-scoped: audit integrity must not
 * depend on the request's tenant being set correctly, and the system trail has
 * no tenant. Reads are authorized explicitly by the AuditQuery module.
 *
 * The chain itself — append, verify, checkpoint — is cboxdk/laravel-audit-chain's; this
 * model is the platform's row in it, over the `audit_logs` table the platform has always
 * used, partitioned by `environment_id`.
 *
 * @property string $id
 * @property string $scope
 * @property string|null $organization_id
 * @property int $sequence
 * @property ActorType $actor_type
 * @property string|null $actor_id
 * @property string $action
 * @property string|null $target_type
 * @property string|null $target_id
 * @property array<string, mixed> $context
 * @property string|null $ip
 * @property string|null $environment_id
 * @property string $prev_hash
 * @property string $hash
 * @property Carbon|null $recorded_at
 */
class AuditEntry extends ChainEntry implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    public $timestamps = false;

    protected $table = 'audit_logs';

    protected $guarded = [];

    /**
     * A chain is addressed by (environment, scope).
     */
    public function chainPartitionColumn(): string
    {
        return 'environment_id';
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'sequence' => 'integer',
            'actor_type' => ActorType::class,
            'context' => 'array',
            'recorded_at' => 'datetime',
        ];
    }
}
