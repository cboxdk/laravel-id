<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Test-only model owned by BOTH an environment (hard outer wall) and an
 * organization (inner, roll-up-able) — used to prove the two scopes are
 * orthogonal and that the environment boundary is never crossed by the org escape.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $name
 */
final class EnvThing extends Model implements EnvironmentOwned, TenantOwned
{
    use BelongsToEnvironment;
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'env_things';

    protected $guarded = [];
}
