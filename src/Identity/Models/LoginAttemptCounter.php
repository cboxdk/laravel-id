<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Failed password attempts for one subject, and the lockout they triggered.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $user_id
 * @property int $failures
 * @property Carbon|null $window_started_at
 * @property Carbon|null $locked_until
 */
class LoginAttemptCounter extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'login_attempt_counters';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'failures' => 'integer',
            'window_started_at' => 'datetime',
            'locked_until' => 'datetime',
        ];
    }

    public function isLocked(): bool
    {
        return $this->locked_until !== null && $this->locked_until->isFuture();
    }
}
