<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Identity\Enums\UserStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A global user identity — one person, one row, independent of organizations.
 * Org linkage is via memberships. The password hash (argon2id recommended) is
 * hidden and only touched through the UserDirectory.
 *
 * @property string $id
 * @property string $email
 * @property string|null $name
 * @property string|null $password
 * @property UserStatus $status
 * @property Carbon|null $email_verified_at
 */
final class User extends Model
{
    use HasUlids;

    protected $table = 'users';

    protected $guarded = [];

    /**
     * @var list<string>
     */
    protected $hidden = ['password'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => UserStatus::class,
            'email_verified_at' => 'datetime',
        ];
    }
}
