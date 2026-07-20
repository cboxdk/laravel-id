<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A CIBA (OpenID Connect Client-Initiated Backchannel Authentication) request in
 * progress. The `auth_req_id` is stored only as a SHA-256 hash (the raw value is
 * the client's polling secret); the user is resolved from the request's
 * `login_hint` and bound as `user_id` up front, so the host knows who to notify.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $auth_req_id_hash
 * @property string $client_id
 * @property string $user_id
 * @property string|null $organization_id
 * @property array<int, string> $scopes
 * @property string|null $binding_message
 * @property string|null $nonce
 * @property string $status
 * @property int $interval
 * @property Carbon|null $last_polled_at
 * @property Carbon|null $approved_at
 * @property Carbon $expires_at
 */
class BackchannelAuthRequest extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'ciba_requests';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'last_polled_at' => 'datetime',
            'approved_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
