<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Models;

use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A single append-only audit entry. Not tenant-scoped: audit integrity must not
 * depend on the request's tenant being set correctly, and the system trail has
 * no tenant. Reads are authorized explicitly by the AuditQuery module.
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
 * @property string $prev_hash
 * @property string $hash
 * @property Carbon|null $recorded_at
 */
final class AuditEntry extends Model
{
    use HasUlids;

    public $timestamps = false;

    protected $table = 'audit_logs';

    protected $guarded = [];

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
