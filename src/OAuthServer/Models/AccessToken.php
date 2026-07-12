<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A record of an issued access token, keyed by its `jti`, so tokens can be
 * revoked and introspected even though they are stateless JWTs.
 *
 * @property string $id
 * @property string $jti
 * @property string $client_id
 * @property string|null $user_id
 * @property string|null $organization_id
 * @property array<int, string> $scopes
 * @property string|null $audience
 * @property Carbon $expires_at
 * @property Carbon|null $revoked_at
 */
final class AccessToken extends Model
{
    use HasUlids;

    protected $table = 'oauth_access_tokens';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }
}
