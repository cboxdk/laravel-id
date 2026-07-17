<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * An account member's passkey. NOT environment-owned — account members are above
 * every environment.
 *
 * @property string $id
 * @property string $account_member_id
 * @property string $credential_id
 * @property string $public_key
 * @property int $sign_count
 * @property array<int, string> $transports
 * @property string|null $name
 * @property Carbon|null $created_at
 */
final class AccountWebAuthnCredential extends Model
{
    use HasUlids;

    protected $table = 'account_webauthn_credentials';

    protected $guarded = [];

    /**
     * @return BelongsTo<AccountMember, $this>
     */
    public function member(): BelongsTo
    {
        return $this->belongsTo(AccountMember::class, 'account_member_id');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'sign_count' => 'integer',
            'transports' => 'array',
        ];
    }
}
