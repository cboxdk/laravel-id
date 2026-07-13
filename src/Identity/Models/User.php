<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A global user identity — one person, one row, independent of organizations.
 * Org linkage is via memberships. The password hash (argon2id recommended) is
 * hidden and only touched through the default Subjects resolver. This model is
 * only the platform's built-in store; a host app can resolve subjects from its
 * own model(s) instead (see Cbox\Id\Identity\Contracts\Subjects).
 *
 * @property string $id
 * @property string $environment_id
 * @property string $email
 * @property string|null $name
 * @property string|null $password
 * @property UserStatus $status
 * @property Carbon|null $email_verified_at
 */
class User extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $guarded = [];

    /**
     * The table is configurable so the platform can map onto a host's existing
     * user table instead of imposing its own.
     */
    public function getTable(): string
    {
        $configured = config('cbox-id.tables.users');

        return is_string($configured) && $configured !== '' ? $configured : 'users';
    }

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
