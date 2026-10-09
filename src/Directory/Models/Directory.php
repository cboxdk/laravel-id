<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Models;

use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Enums\DirectoryStatus;
use Cbox\Id\Directory\Enums\DirectorySyncStatus;
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
 * Neither secret is ever serialized: both are `$hidden`, so a directory handed to a JSON
 * response, a log line or a queue payload carries neither the sealed credentials nor the
 * token hash.
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
 * @property int|null $sync_interval_minutes
 * @property Carbon|null $last_sync_started_at
 * @property DirectorySyncStatus|null $last_sync_status
 * @property array<string, mixed>|null $last_sync_stats
 * @property string|null $sync_cursor
 * @property Carbon|null $last_full_sync_at
 */
class Directory extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'directories';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['credentials', 'bearer_token_hash'];

    /** The shortest interval a directory may be pulled at; the scheduler ticks this often. */
    public const int MIN_SYNC_INTERVAL_MINUTES = 15;

    /** The longest: a day. A directory pulled less often than that is not being kept in step. */
    public const int MAX_SYNC_INTERVAL_MINUTES = 1440;

    /** How often this directory is pulled: its own interval, else the configured default. */
    public function syncIntervalMinutes(): int
    {
        if ($this->sync_interval_minutes !== null) {
            return $this->sync_interval_minutes;
        }

        $default = config('cbox-id.directory.default_interval_minutes', 60);

        return is_numeric($default) ? max(self::MIN_SYNC_INTERVAL_MINUTES, (int) $default) : 60;
    }

    /**
     * Whether a scheduled pull should run now.
     *
     * Measured from when the last run STARTED, so a run that keeps failing is retried at
     * the directory's pace rather than every tick. A minute of slack, so an hourly directory
     * on a fifteen-minute tick is pulled every hour rather than every hour and a quarter.
     */
    public function isDueForSync(?Carbon $now = null): bool
    {
        if (! $this->provider->isPull() || $this->status !== DirectoryStatus::Active) {
            return false;
        }

        if ($this->last_sync_started_at === null) {
            return true;
        }

        $now ??= Carbon::now();

        return $this->last_sync_started_at->copy()->addMinutes($this->syncIntervalMinutes())->subMinute()->lte($now);
    }

    /** When the next scheduled pull is due, or null for a directory nobody pulls. */
    public function nextSyncAt(): ?Carbon
    {
        if (! $this->provider->isPull() || $this->status !== DirectoryStatus::Active) {
            return null;
        }

        return $this->last_sync_started_at?->copy()->addMinutes($this->syncIntervalMinutes());
    }

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
            'sync_interval_minutes' => 'integer',
            'last_sync_started_at' => 'datetime',
            'last_sync_status' => DirectorySyncStatus::class,
            'last_sync_stats' => 'array',
            'last_full_sync_at' => 'datetime',
        ];
    }
}
