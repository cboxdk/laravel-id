<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Models;

use Cbox\Id\Federation\Enums\ConnectionStatus;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A per-org SSO connection to an external IdP. The IdP config (entity id, SSO
 * URL, signing certificate, client secret…) is stored sealed via the Crypto
 * kernel; it is only opened when validating an assertion. Each connection has
 * its own ACS/callback route keyed by its id, so multi-connection routing is
 * unambiguous.
 *
 * @property string $id
 * @property string $organization_id
 * @property ConnectionType $type
 * @property string $name
 * @property ConnectionStatus $status
 * @property string $config_encrypted
 * @property array<string, mixed> $mappings
 */
final class Connection extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'connections';

    protected $guarded = [];

    public function secretContext(): string
    {
        return 'cbox-id:connection:'.$this->id;
    }

    public function isActive(): bool
    {
        return $this->status === ConnectionStatus::Active;
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => ConnectionType::class,
            'status' => ConnectionStatus::class,
            'mappings' => 'array',
        ];
    }
}
