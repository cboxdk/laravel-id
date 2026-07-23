<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Enums\AccountMemberStatus;
use Cbox\Id\Platform\Enums\AccountRole;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
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
 * @property AccountRole $role
 * @property bool $all_environments
 * @property string $password
 * @property AccountMemberStatus $status
 * @property int $session_version
 * @property Carbon|null $last_login_at
 */
class AccountMember extends Model
{
    use HasUlids;

    protected $table = 'account_members';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['password'];

    public function isActive(): bool
    {
        return $this->status === AccountMemberStatus::Active;
    }

    /**
     * @return BelongsTo<Account, $this>
     */
    public function account(): BelongsTo
    {
        return $this->belongsTo(Account::class);
    }

    /**
     * The environments this member is explicitly granted — only meaningful when
     * {@see $all_environments} is false.
     *
     * @return BelongsToMany<Environment, $this>
     */
    public function environments(): BelongsToMany
    {
        return $this->belongsToMany(Environment::class, 'account_member_environments');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'role' => AccountRole::class,
            'status' => AccountMemberStatus::class,
            'all_environments' => 'boolean',
            'password' => 'hashed',
            'last_login_at' => 'datetime',
        ];
    }
}
