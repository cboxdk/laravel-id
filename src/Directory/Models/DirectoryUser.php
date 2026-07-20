<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * A SCIM resource synced from the customer's directory, linked to a local user.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $directory_id
 * @property string $external_id
 * @property array<string, mixed> $resource
 * @property string|null $user_id
 * @property bool $active
 */
class DirectoryUser extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'directory_users';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'resource' => 'array',
            'active' => 'boolean',
        ];
    }
}
