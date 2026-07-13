<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A refresh token, stored only as a SHA-256 hash. Rotation is single-use:
 * presenting a token consumes it and mints a successor in the same `family_id`.
 * Re-presenting a consumed token is treated as theft and revokes the family.
 *
 * @property string $id
 * @property string $token_hash
 * @property string $family_id
 * @property string $client_id
 * @property string|null $user_id
 * @property string|null $organization_id
 * @property array<int, string> $scopes
 * @property string|null $audience
 * @property string|null $jkt
 * @property Carbon|null $consumed_at
 * @property Carbon|null $revoked_at
 * @property Carbon $expires_at
 */
final class RefreshToken extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_refresh_tokens';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'consumed_at' => 'datetime',
            'revoked_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
