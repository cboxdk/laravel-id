<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An operator's second-factor enrolment. The TOTP secret is stored sealed
 * (Crypto SecretBox) and only opened to verify a code. Not environment-owned —
 * operators live above every environment.
 *
 * @property string $id
 * @property string $operator_id
 * @property string $type
 * @property string $secret_encrypted
 * @property Carbon|null $confirmed_at
 * @property int|null $last_used_step
 */
final class OperatorMfaFactor extends Model
{
    use HasUlids;

    protected $table = 'operator_mfa_factors';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'confirmed_at' => 'datetime',
            'last_used_step' => 'integer',
        ];
    }
}
