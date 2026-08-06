<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\OAuthServer\Enums\ServiceAccountStatus;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A machine identity (M2M), backed by a confidential client.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $organization_id
 * @property string $name
 * @property string $client_id
 * @property string|null $rotated_from
 * @property ServiceAccountStatus $status
 * @property Carbon|null $retired_at
 */
class ServiceAccount extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_service_accounts';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => ServiceAccountStatus::class,
        ];
    }
}
