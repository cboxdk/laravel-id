<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A device authorization grant in progress (RFC 8628).
 *
 * @property string $id
 * @property string $device_code_hash
 * @property string $user_code
 * @property string $client_id
 * @property array<int, string> $scopes
 * @property string $status
 * @property string|null $user_id
 * @property string|null $organization_id
 * @property int $interval
 * @property Carbon|null $last_polled_at
 * @property Carbon $expires_at
 */
final class DeviceCode extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'device_codes';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'last_polled_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }
}
