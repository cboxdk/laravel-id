<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A password a subject used previously, retained ONLY as its hash so a reuse policy can
 * be enforced without ever holding a readable credential.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $user_id
 * @property string $password_hash
 * @property Carbon|null $created_at
 */
class PasswordHistoryEntry extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'password_history';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['password_hash'];
}
