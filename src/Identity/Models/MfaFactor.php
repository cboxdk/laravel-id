<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A second-factor enrolment. The TOTP secret is stored sealed (Crypto SecretBox)
 * and only opened to verify a code.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $user_id
 * @property string $type
 * @property string $secret_encrypted
 * @property Carbon|null $confirmed_at
 * @property int|null $last_used_step
 */
class MfaFactor extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
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
