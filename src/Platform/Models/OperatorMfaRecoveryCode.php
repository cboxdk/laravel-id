<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A single-use operator recovery code, stored only as a hash. Consumed by
 * setting `used_at`; regeneration deletes the operator's remaining codes and
 * issues a fresh batch. Not environment-owned.
 *
 * @property string $id
 * @property string $operator_id
 * @property string $code_hash
 * @property Carbon|null $used_at
 */
class OperatorMfaRecoveryCode extends Model
{
    use HasUlids;

    protected $table = 'operator_mfa_recovery_codes';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['used_at' => 'datetime'];
    }
}
