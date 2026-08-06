<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A single delivered one-time passcode. Environment-owned, so a challenge issued
 * in one environment is structurally invisible to any other (the hard scope).
 *
 * Only the KEYED hash of the code (`code_hash`) is ever stored — never the
 * plaintext code. The row is single-use (`consumed_at`), TTL-bounded
 * (`expires_at`) and attempt-capped (`attempts` / `max_attempts`).
 *
 * @property string $id
 * @property string $environment_id
 * @property string $purpose
 * @property string $channel
 * @property string $recipient
 * @property string $code_hash
 * @property Carbon $expires_at
 * @property int $attempts
 * @property int $max_attempts
 * @property Carbon|null $consumed_at
 */
class OtpChallenge extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'otp_challenges';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
            'attempts' => 'integer',
            'max_attempts' => 'integer',
        ];
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }

    public function isConsumed(): bool
    {
        return $this->consumed_at !== null;
    }

    public function isLocked(): bool
    {
        return $this->attempts >= $this->max_attempts;
    }
}
