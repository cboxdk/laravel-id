<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Platform\Enums\AccountRole;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * An account API key — a hashed, role-carrying credential for the account
 * management plane. Only the hash is persisted; the plaintext lives only in the
 * response that created it.
 *
 * @property string $id
 * @property string $account_id
 * @property string $name
 * @property string $prefix
 * @property string $token_hash
 * @property AccountRole $role
 * @property Carbon|null $last_used_at
 * @property Carbon|null $expires_at
 * @property Carbon|null $revoked_at
 */
class AccountApiKey extends Model
{
    use HasUlids;

    protected $table = 'account_api_keys';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['token_hash'];

    /** Usable only while neither revoked nor past its expiry. */
    public function isActive(): bool
    {
        if ($this->revoked_at !== null) {
            return false;
        }

        return $this->expires_at === null || $this->expires_at->isFuture();
    }

    /**
     * @return BelongsTo<Account, $this>
     */
    public function account(): BelongsTo
    {
        return $this->belongsTo(Account::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'role' => AccountRole::class,
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }
}
