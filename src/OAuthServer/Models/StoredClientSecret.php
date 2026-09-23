<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One secret an OAuth client may authenticate with — stored as its SHA-256 only.
 *
 * A client holds several while a rotation is in flight: the new one with no expiry, the
 * ones it replaces with an `expires_at` at the end of the grace period. Any live one
 * authenticates. `hint` is the last few characters of the plaintext, so an operator can
 * tell which one a deployment still holds; it is null for a secret that predates this
 * table, because the plaintext was never kept.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $oauth_client_id
 * @property string $secret_hash
 * @property string|null $hint
 * @property Carbon|null $expires_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class StoredClientSecret extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_client_secrets';

    protected $guarded = [];

    /**
     * The hash is never serialized: a model handed to a page or an API resource by
     * mistake must not carry a credential's verifier with it.
     *
     * @var list<string>
     */
    protected $hidden = ['secret_hash'];

    /**
     * Live at this instant: no expiry, or one still in the future.
     *
     * @param  Builder<self>  $query
     */
    public function scopeLive(Builder $query): void
    {
        $query->where(fn (Builder $q): Builder => $q
            ->whereNull($q->qualifyColumn('expires_at'))
            ->orWhere($q->qualifyColumn('expires_at'), '>', now()));
    }

    public function isLive(): bool
    {
        return $this->expires_at === null || $this->expires_at->isFuture();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'last_used_at' => 'datetime',
        ];
    }
}
