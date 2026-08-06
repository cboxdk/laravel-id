<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Cbox\Id\Organization\GroupService;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * An organization-local group of users, usable as a grant subject: granting a
 * role to a group grants it to every member, resolved through the relationship
 * store's userset expansion.
 *
 * This model is metadata only (name, org). Membership lives as relationship
 * tuples — see {@see GroupService} — never as rows here,
 * so there is a single source of truth for who is in a group.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $name
 */
class UserGroup extends Model implements EnvironmentOwned, TenantOwned
{
    use BelongsToEnvironment;
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'user_groups';

    protected $guarded = [];
}
