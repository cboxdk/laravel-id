<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An explicit authorization for one agent client to lease one vault secret.
 *
 * The vault is deny-by-default: a lease is refused unless a live (non-revoked)
 * grant exists for the exact (secret, client) pair in this environment. A grant
 * may cap how long a leased value can be held (`max_ttl_seconds`), which can only
 * shorten the vault-wide default, never extend it.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $secret_id
 * @property string $client_id
 * @property int|null $max_ttl_seconds
 * @property Carbon|null $revoked_at
 */
class VaultGrant extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'vault_grants';

    protected $guarded = [];

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'max_ttl_seconds' => 'integer',
            'revoked_at' => 'datetime',
        ];
    }
}
