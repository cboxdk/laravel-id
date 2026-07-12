<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A user's membership of an organization (org ↔ user, with a coarse role).
 * Tenant-owned: reads are automatically scoped to the current organization.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $user_id
 * @property string $role
 * @property MembershipStatus $status
 * @property string|null $invited_by
 */
final class Membership extends Model implements TenantOwned
{
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'memberships';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => MembershipStatus::class,
        ];
    }
}
