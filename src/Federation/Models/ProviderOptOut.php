<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Models;

use Cbox\Id\Federation\Contracts\SignInProviders;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * One organization not offering one of its environment's sign-in providers on its own
 * sign-in page — see {@see SignInProviders::stopInheriting()}.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $provider the catalogue key, e.g. `google`
 */
class ProviderOptOut extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'sign_in_provider_opt_outs';

    protected $guarded = [];
}
