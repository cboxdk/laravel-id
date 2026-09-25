<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Models;

use Cbox\AuditChain\Models\ChainCheckpoint;
use Cbox\AuditChain\ValueObjects\ChainKey;
use Cbox\Id\Kernel\Audit\DatabaseAuditLog;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;

/**
 * A signed checkpoint over a chain head. The `signature` is a JWT signed by the
 * Crypto kernel over {scope, up_to_sequence, root_hash}; anchor it externally
 * for a tamper-*proof* guarantee.
 *
 * @property string $id
 * @property string|null $environment_id
 * @property string $scope
 * @property string|null $organization_id
 * @property int $up_to_sequence
 * @property string $root_hash
 * @property string $signature
 */
class AuditCheckpoint extends ChainCheckpoint implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'audit_checkpoints';

    protected $guarded = [];

    /**
     * A chain is addressed by (environment, scope).
     */
    public function chainPartitionColumn(): string
    {
        return 'environment_id';
    }

    /**
     * A checkpoint also records the organization whose chain it attests — which is the
     * chain's scope, or none for the environment's own `__system__` trail.
     */
    public function assignChainKey(ChainKey $key): void
    {
        parent::assignChainKey($key);

        $this->setAttribute('organization_id', $key->scope === DatabaseAuditLog::SYSTEM_SCOPE ? null : $key->scope);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'up_to_sequence' => 'integer',
        ];
    }
}
