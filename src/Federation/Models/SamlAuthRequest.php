<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An outstanding SP-initiated SAML AuthnRequest, kept so the ACS can enforce that
 * an assertion's InResponseTo matches a request this SP actually issued.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $request_id
 * @property string $connection_id
 * @property Carbon $expires_at
 * @property Carbon|null $consumed_at
 */
class SamlAuthRequest extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'saml_auth_requests';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['expires_at' => 'datetime', 'consumed_at' => 'datetime'];
    }
}
