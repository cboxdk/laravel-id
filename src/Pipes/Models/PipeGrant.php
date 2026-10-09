<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An app (an OAuth `client_id`) allowed to lease the tokens people connected through one
 * pipe. Deny-by-default: an app with no row here is refused, uniformly, whatever its
 * token's scopes say. Revoking deletes the row.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $pipe_id
 * @property string $client_id
 * @property Carbon|null $created_at
 */
class PipeGrant extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'pipe_grants';

    protected $guarded = [];
}
