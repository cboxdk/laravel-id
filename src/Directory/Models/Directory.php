<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Models;

use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Enums\DirectoryStatus;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A per-org directory connection. For a SCIM (push) directory the bearer token
 * (used by the customer's IdP) is stored only as a SHA-256 hash; for a pull
 * directory (Google Workspace, Entra) the provider credentials are sealed in
 * `credentials` (Crypto SecretBox).
 *
 * @property string $id
 * @property string $organization_id
 * @property string $name
 * @property DirectoryProvider $provider
 * @property string|null $bearer_token_hash
 * @property string|null $credentials
 * @property DirectoryStatus $status
 * @property array<string, mixed> $mappings
 * @property Carbon|null $last_synced_at
 * @property string|null $last_sync_error
 */
class Directory extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'directories';

    protected $guarded = [];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'provider' => DirectoryProvider::class,
            'status' => DirectoryStatus::class,
            'mappings' => 'array',
            'last_synced_at' => 'datetime',
        ];
    }
}
