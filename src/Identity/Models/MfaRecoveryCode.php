<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A single-use MFA recovery code, stored only as a hash. Consumed by setting
 * `used_at`; regeneration deletes the user's remaining codes and issues a fresh
 * batch.
 *
 * @property string $id
 * @property string $user_id
 * @property string $code_hash
 * @property Carbon|null $used_at
 */
final class MfaRecoveryCode extends Model
{
    use HasUlids;

    protected $table = 'mfa_recovery_codes';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['used_at' => 'datetime'];
    }
}
