<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * An account member — a login identity for the account's root console. Like an
 * operator it is NOT environment-owned: it authenticates once at the platform
 * root and can then step into any environment its account owns. Distinct from a
 * Subject (an end-user inside an environment), which never sees this plane.
 *
 * @property string $id
 * @property string $account_id
 * @property string $email
 * @property string|null $name
 * @property string $password
 * @property string $status
 * @property Carbon|null $last_login_at
 */
final class AccountMember extends Model
{
    use HasUlids;

    protected $table = 'account_members';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['password'];

    public function isActive(): bool
    {
        return $this->status === 'active';
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
            'password' => 'hashed',
            'last_login_at' => 'datetime',
        ];
    }
}
