<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Enums\AccountStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * An account — the login/identity umbrella and the billing CUSTOMER: it owns members
 * and payment methods, and it owns environments transitively through its PROJECTS. It
 * sits ABOVE the tenancy (like operators), so it is deliberately NOT environment-owned:
 * these rows are global.
 *
 * The plan/billing anchor is NOT here — it moved to the {@see Project}
 * ({@see Project::$environment_limit}), so one account can own several
 * independently-billed IdP products. This model's own `environment_limit` is retained
 * only as the seed the account's first ("Default") project inherits at provision time;
 * per-project allowance is what the framework actually enforces.
 *
 * @property string $id
 * @property string $name
 * @property AccountStatus $status
 * @property int $environment_limit Seed for the first project's allowance; NOT the enforced limit.
 * @property array<string, mixed> $settings
 */
class Account extends Model
{
    use HasUlids;

    protected $table = 'accounts';

    protected $guarded = [];

    public function isActive(): bool
    {
        return $this->status === AccountStatus::Active;
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
            'status' => AccountStatus::class,
            'environment_limit' => 'integer',
            'settings' => 'array',
        ];
    }
}
