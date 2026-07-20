<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Organization\Models\Environment;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A project — one IdP product within an account, between the account (the login /
 * identity umbrella) and its environments (the product's prod/staging/dev stages).
 * The Clerk "Application" / Auth0 "Tenant" layer: one account can own several
 * independently-billed projects.
 *
 * The plan/billing anchor lives here: `environment_limit` is THIS project's plan
 * allowance, and a future subscription attaches to the project — so two products
 * under one account bill separately. Like the account, a project sits ABOVE
 * environments and is not environment-scoped.
 *
 * @property string $id
 * @property string $account_id
 * @property string $name
 * @property string $slug
 * @property string $status
 * @property int $environment_limit
 * @property array<string, mixed> $settings
 */
class Project extends Model
{
    use HasUlids;

    protected $table = 'projects';

    protected $guarded = [];

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /**
     * The account that owns this project (the login/identity umbrella above it).
     *
     * @return BelongsTo<Account, $this>
     */
    public function account(): BelongsTo
    {
        return $this->belongsTo(Account::class);
    }

    /**
     * The environments (prod/staging/dev stages) of this project. Not
     * environment-scoped — the project is the owner, above the boundary.
     *
     * @return HasMany<Environment, $this>
     */
    public function environments(): HasMany
    {
        return $this->hasMany(Environment::class);
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
