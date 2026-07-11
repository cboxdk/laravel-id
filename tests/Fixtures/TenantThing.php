<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * Test-only tenant-owned model used to prove the isolation guarantees.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $name
 */
final class TenantThing extends Model implements TenantOwned
{
    use BelongsToTenant;
    use HasUlids;

    protected $table = 'tenant_things';

    protected $guarded = [];
}
