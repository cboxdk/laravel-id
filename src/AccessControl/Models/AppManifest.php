<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * The last-synced authorization manifest for an app (OAuth client) — its declared
 * version + a content checksum, so a re-sync with an unchanged manifest is a cheap
 * no-op. The declared roles/permissions themselves live in the roles/permissions
 * tables (scoped by client_id); this row just tracks sync state.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $client_id
 * @property string|null $version
 * @property string $checksum
 * @property Carbon $synced_at
 */
class AppManifest extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'app_manifests';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'synced_at' => 'datetime',
        ];
    }
}
