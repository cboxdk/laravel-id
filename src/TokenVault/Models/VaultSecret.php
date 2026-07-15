<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A downstream third-party credential (an API key, or an OAuth access/refresh
 * token for a service an AI agent calls) held on behalf of an environment.
 *
 * The credential is stored SEALED via the Crypto SecretBox — never a plain hash,
 * because unlike a platform-issued token the vault must be able to REPLAY this
 * value to the downstream provider, so it must be recoverable, not merely
 * verifiable. The sealed blob is opened only at lease time, for an authorized
 * agent, and the plaintext is never persisted unsealed, logged, or audited.
 *
 * `key_version` records which master-key generation sealed the blob; the crypto
 * kernel has no automatic master-key rotation, so a re-seal is a manual
 * operation and this column makes a future migration auditable.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $name
 * @property string $provider
 * @property string $secret_encrypted
 * @property int $key_version
 * @property string|null $owner_type
 * @property string|null $owner_id
 * @property Carbon|null $expires_at
 * @property Carbon|null $revoked_at
 * @property Carbon|null $rotated_at
 */
final class VaultSecret extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'vault_secrets';

    protected $guarded = [];

    /**
     * The AEAD context bound into the sealed blob. Tied to the immutable primary
     * key, so a ciphertext sealed for one secret can never be opened against
     * another row (or another column).
     */
    public function secretContext(): string
    {
        return 'cbox-id:vault-secret:'.$this->id;
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'key_version' => 'integer',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
            'rotated_at' => 'datetime',
        ];
    }
}
