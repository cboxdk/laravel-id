<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

/**
 * A user's membership of an organization (org ↔ user, with a coarse role).
 * Tenant-owned: reads are automatically scoped to the current organization.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $user_id
 * @property MembershipRole $role
 * @property MembershipStatus $status
 * @property string|null $invited_by
 * @property bool $all_environments
 */
class Membership extends Model implements EnvironmentOwned, TenantOwned
{
    use BelongsToEnvironment;
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'memberships';

    protected $guarded = [];

    /**
     * The environments this membership is restricted TO, when {@see $all_environments} is
     * false. Empty and meaningless while it is true — the grants are the restriction, not
     * the access, so a member with the boolean set has access to everything the
     * organization owns regardless of what rows are here.
     *
     * Crosses the tenancy boundary on purpose, as its account-plane predecessor did: the
     * membership lives in the platform root and the environments it names are the tenant
     * environments the organization owns.
     *
     * @return BelongsToMany<Environment, $this>
     */
    public function environments(): BelongsToMany
    {
        return $this->belongsToMany(Environment::class, 'membership_environments');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'role' => MembershipRole::class,
            'status' => MembershipStatus::class,
            'all_environments' => 'boolean',
        ];
    }
}
