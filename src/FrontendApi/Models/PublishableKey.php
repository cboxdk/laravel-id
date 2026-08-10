<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Models;

use Carbon\CarbonInterface;
use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A key a browser may hold, and the origins allowed to hold it.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $key
 * @property KeyMode $mode
 * @property string $name
 * @property CarbonInterface|null $last_used_at
 * @property CarbonInterface|null $revoked_at
 */
class PublishableKey extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'frontend_api_keys';

    protected $guarded = [];

    /** @return HasMany<AllowedOrigin, $this> */
    public function origins(): HasMany
    {
        return $this->hasMany(AllowedOrigin::class, 'frontend_api_key_id');
    }

    /**
     * Whether this key may still be used.
     *
     * Revocation is a timestamp rather than a delete so a key that surfaces in a log six
     * months from now is still identifiable as one we withdrew, and when.
     */
    public function isActive(): bool
    {
        return $this->revoked_at === null;
    }

    /**
     * Whether this exact origin is allowed to use the key.
     *
     * A BYTE-FOR-BYTE COMPARISON against the loaded allow-list, and deliberately nothing
     * cleverer. Every subtle version of this check has been the bug: a suffix match makes
     * `https://acme.com.evil.test` pass for `https://acme.com`; a `str_contains` makes
     * anything containing the string pass; a "wildcard subdomain" needs a public-suffix
     * list to be safe and nobody carries one. An origin is a short, exact string, and
     * exact is the only comparison that cannot be tricked.
     */
    public function allowsOrigin(string $origin): bool
    {
        if ($origin === '') {
            return false;
        }

        return $this->origins
            ->contains(static fn (AllowedOrigin $allowed): bool => hash_equals($allowed->origin, $origin));
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'mode' => KeyMode::class,
            'last_used_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }
}
