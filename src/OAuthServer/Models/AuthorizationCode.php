<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

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
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 */
final class AuthorizationCode extends Model
{
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
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }
}
