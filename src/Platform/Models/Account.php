<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Organization\Models\Environment;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * An account — the customer's workspace, the plane that owns environments. It
 * sits ABOVE environments (like operators), so it is deliberately NOT
 * environment-owned: these rows are global.
 *
 * The account is where the plan/billing anchor lives. `environment_limit` is the
 * plan's environment allowance — the dial that turns "a plan with 2 environments"
 * into an enforceable rule.
 *
 * @property string $id
 * @property string $name
 * @property string $status
 * @property int $environment_limit
 * @property array<string, mixed> $settings
 */
final class Account extends Model
{
    use HasUlids;

    protected $table = 'accounts';

    protected $guarded = [];

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /**
     * The environments this account owns. Not environment-scoped — the account
     * is the owner, above the boundary.
     *
     * @return HasMany<Environment, $this>
     */
    public function environments(): HasMany
    {
        return $this->hasMany(Environment::class);
    }

    /**
     * The IdP products (Clerk "Applications") this account owns. Environments nest
     * under a project; the account owns environments transitively through them.
     *
     * @return HasMany<Project, $this>
     */
    public function projects(): HasMany
    {
        return $this->hasMany(Project::class);
    }

    /**
     * The login identities that administer this account.
     *
     * @return HasMany<AccountMember, $this>
     */
    public function members(): HasMany
    {
        return $this->hasMany(AccountMember::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'environment_limit' => 'integer',
            'settings' => 'array',
        ];
    }
}
