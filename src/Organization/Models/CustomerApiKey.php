<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Carbon\Carbon;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Cbox\Id\Organization\Contracts\CustomerApiKeys;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A customer API key: a user API token BOUND TO ONE APP (public form
 * `{app prefix}_…`, e.g. `ctx_live_…`).
 *
 * It lives in the same table as the personal `cbid_pat_` tokens ({@see UserApiToken}) —
 * same hashing, same tenancy, same revocation — and is told apart by `client_id`: a row
 * with one is a customer key, a row without one is a personal token. Each model carries
 * a global scope for its half, so neither can ever load the other's rows.
 *
 * `permissions` is the subset of the app's permissions the key was issued with. It is a
 * CEILING, not a grant: every verification intersects it with what the holder holds for
 * the app at that moment ({@see CustomerApiKeys::verify()}), so a downgraded holder's
 * key loses the permission on the next request.
 *
 * The plain key is shown once at issuance; only its SHA-256 hash is stored.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $user_id
 * @property string $client_id
 * @property string|null $name
 * @property string $prefix
 * @property string $token_hash
 * @property list<string> $permissions
 * @property Carbon|null $expires_at
 * @property Carbon|null $revoked_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class CustomerApiKey extends Model implements EnvironmentOwned, TenantOwned
{
    use BelongsToEnvironment;
    use BelongsToTenant;
    use HasUlids;

    /** The global scope that keeps this model to rows bound to an app. */
    public const SCOPE = 'customer_api_key';

    protected $table = 'user_api_tokens';

    protected $guarded = [];

    protected $hidden = ['token_hash'];

    protected static function booted(): void
    {
        static::addGlobalScope(self::SCOPE, static function (Builder $query): void {
            $query->whereNotNull($query->qualifyColumn('client_id'));
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'permissions' => 'array',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'last_used_at' => 'datetime',
        ];
    }

    /** Not revoked and not past its expiry. Says nothing about the holder — see verify(). */
    public function isActive(): bool
    {
        return $this->revoked_at === null
            && ($this->expires_at === null || $this->expires_at->isFuture());
    }
}
