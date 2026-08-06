<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A standing requirement for a subject to choose a new password, and the expiry of the
 * temporary credential an administrator handed them.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $user_id
 * @property Carbon|null $expires_at
 * @property string|null $set_by_type
 * @property string|null $set_by_id
 */
class PasswordChangeRequirement extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'password_change_requirements';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
        ];
    }

    /** A temporary credential is spent once its expiry passes. */
    public function hasExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }
}
