<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $environment_id
 * @property string $name
 * @property list<string> $readers
 * @property list<string> $writers
 * @property array<string, string> $webhooks
 */
class PropertyNamespace extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'user_property_namespaces';

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['readers' => 'array', 'writers' => 'array', 'webhooks' => 'array'];
    }
}
