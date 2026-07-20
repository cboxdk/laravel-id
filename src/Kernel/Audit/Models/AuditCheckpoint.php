<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A signed checkpoint over a chain head. The `signature` is a JWT signed by the
 * Crypto kernel over {scope, up_to_sequence, root_hash}; anchor it externally
 * for a tamper-*proof* guarantee.
 *
 * @property string $id
 * @property string $scope
 * @property string|null $organization_id
 * @property int $up_to_sequence
 * @property string $root_hash
 * @property string $signature
 */
class AuditCheckpoint extends Model
{
    use HasUlids;

    protected $table = 'audit_checkpoints';

    protected $guarded = [];

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
