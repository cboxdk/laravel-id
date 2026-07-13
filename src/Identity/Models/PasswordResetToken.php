<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A single-use, short-lived password-reset token. Only the SHA-256 hash is
 * stored; the raw token is emailed once.
 *
 * @property string $id
 * @property string $email
 * @property string $token_hash
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 */
final class PasswordResetToken extends Model
{
    use HasUlids;

    protected $table = 'password_reset_tokens';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
