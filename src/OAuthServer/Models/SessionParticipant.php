<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A relying party a sign-in session signed a person in to — the record Back-Channel
 * Logout reads to know whom to tell when that session ends. `ended_at` is set once the
 * relying party has been notified, so a repeated logout notifies nobody twice.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $session_id
 * @property string $user_id
 * @property string $client_id
 * @property string|null $organization_id
 * @property Carbon|null $ended_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class SessionParticipant extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_session_participants';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'ended_at' => 'datetime',
        ];
    }
}
