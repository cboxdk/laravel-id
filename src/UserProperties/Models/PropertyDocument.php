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
 * @property string $user_id
 * @property string $namespace
 * @property \stdClass $data
 * @property int $version
 */
class PropertyDocument extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'user_property_documents';

    protected $guarded = [];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['data' => 'object', 'version' => 'integer'];
    }
}
