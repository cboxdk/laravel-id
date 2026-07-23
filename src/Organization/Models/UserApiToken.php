<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Carbon\Carbon;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Cbox\Id\Organization\Enums\TokenScope;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A user-bound API token (public form `cbid_pat_…`): it authenticates AS the
 * user within one organization, carrying a coarse scope plus an optional
 * resource-family restriction. Authorization stays with the user — resolve the
 * token, then resolve the user's effective role; there is no token-specific
 * grant model. The plain token is shown once at issuance; only its SHA-256
 * hash is stored.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $user_id
 * @property string $name
 * @property string $prefix
 * @property string $token_hash
 * @property TokenScope $scope
 * @property array<int, string>|null $resource_families
 * @property Carbon|null $expires_at
 * @property Carbon|null $revoked_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class UserApiToken extends Model implements EnvironmentOwned, TenantOwned
{
    use BelongsToEnvironment;
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'user_api_tokens';

    protected $guarded = [];

    protected $hidden = ['token_hash'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scope' => TokenScope::class,
            'resource_families' => 'array',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'last_used_at' => 'datetime',
        ];
    }

    public function isActive(): bool
    {
        return $this->revoked_at === null
            && ($this->expires_at === null || $this->expires_at->isFuture());
    }

    /**
     * Whether the token may touch a resource family. A null list is an
     * unrestricted token (every family) — the "null ⇒ all" contract.
     */
    public function allowsFamily(string $family): bool
    {
        return $this->resource_families === null
            || in_array($family, $this->resource_families, true);
    }
}
