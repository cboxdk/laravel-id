<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A second-factor enrolment. The TOTP secret is stored sealed (Crypto SecretBox)
 * and only opened to verify a code.
 *
 * @property string $id
 * @property string $user_id
 * @property string $type
 * @property string $secret_encrypted
 * @property Carbon|null $confirmed_at
 * @property int|null $last_used_step
 */
final class MfaFactor extends Model
{
    use HasUlids;

    protected $table = 'mfa_factors';

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
