<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A short-lived, single-use authorization code bound to a client, user, redirect
 * URI and PKCE challenge. Only the SHA-256 hash of the code is stored.
 *
 * @property string $id
 * @property string $code_hash
 * @property string $client_id
 * @property string $user_id
 * @property string|null $organization_id
 * @property string $redirect_uri
 * @property array<int, string> $scopes
 * @property string $pkce_challenge
 * @property string $pkce_method
 * @property string|null $nonce
 * @property int|null $auth_time
 * @property array<int, string>|null $amr
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 */
class AuthorizationCode extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_authorization_codes';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'amr' => 'array',
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
