<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An authenticated session. The `amr` records how the user authenticated
 * (password, mfa, sso…). Stored in `auth_sessions` to avoid colliding with
 * Laravel's own database session driver table.
 *
 * @property string $id
 * @property string $user_id
 * @property string|null $organization_id
 * @property string|null $ip
 * @property string|null $user_agent
 * @property array<int, string> $amr
 * @property Carbon|null $last_active_at
 * @property Carbon $expires_at
 * @property Carbon|null $revoked_at
 */
final class Session extends Model
{
    use HasUlids;

    protected $table = 'auth_sessions';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'amr' => 'array',
            'last_active_at' => 'datetime',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }
}
