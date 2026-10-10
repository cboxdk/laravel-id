<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Pipes\Enums\PipeConnectionStatus;
use Cbox\Id\TokenVault\ValueObjects\VaultOwner;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * One person's connected account at one pipe's provider, bound to
 * (environment, user, pipe).
 *
 * The tokens are NOT on this row. The access token and the refresh token are token-vault
 * secrets owned by the user ({@see VaultOwner::user()}),
 * sealed at rest, leased only through the vault's audited, deny-by-default path, and
 * erased with the person. This row names them and carries what is safe to show: the
 * provider, the granted scopes, when the access token expires, and the non-secret parts of
 * the token response an app needs (Salesforce's `instance_url`).
 *
 * @property string $id
 * @property string $environment_id
 * @property string $pipe_id
 * @property string $provider
 * @property string $user_id
 * @property PipeConnectionStatus $status
 * @property string $access_secret_id
 * @property string|null $refresh_secret_id
 * @property list<string>|null $scopes
 * @property array<string, string>|null $metadata
 * @property string|null $account_label
 * @property Carbon|null $access_expires_at
 * @property Carbon|null $connected_at
 * @property Carbon|null $last_refreshed_at
 * @property Carbon|null $refresh_claimed_until
 * @property int $refresh_failures
 * @property string|null $last_error
 * @property string|null $reauth_reason
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 * @property-read Pipe|null $pipe
 */
class PipeConnection extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'pipe_connections';

    protected $guarded = [];

    /**
     * The vault secret ids are internal plumbing, not something to render: hidden so a
     * host returning the model cannot hand out the handles to a person's tokens.
     */
    protected $hidden = ['access_secret_id', 'refresh_secret_id', 'refresh_claimed_until'];

    /** @return BelongsTo<Pipe, $this> */
    public function pipe(): BelongsTo
    {
        return $this->belongsTo(Pipe::class);
    }

    public function isActive(): bool
    {
        return $this->status === PipeConnectionStatus::Active;
    }

    /**
     * Whether the access token is expired, or will be within `$seconds`. A token with no
     * known expiry never is.
     */
    public function expiresWithin(int $seconds): bool
    {
        return $this->access_expires_at !== null
            && $this->access_expires_at->lte(now()->addSeconds($seconds));
    }

    public function canRefresh(): bool
    {
        return $this->refresh_secret_id !== null;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => PipeConnectionStatus::class,
            'scopes' => 'array',
            'metadata' => 'array',
            'access_expires_at' => 'datetime',
            'connected_at' => 'datetime',
            'last_refreshed_at' => 'datetime',
            'refresh_claimed_until' => 'datetime',
            'refresh_failures' => 'integer',
        ];
    }
}
