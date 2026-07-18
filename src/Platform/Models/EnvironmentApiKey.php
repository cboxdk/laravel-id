<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An environment API key — a hashed, scope-carrying credential for the ENVIRONMENT
 * management plane (orgs, users, directories within one environment). Environment-
 * OWNED via {@see BelongsToEnvironment}: the hard scope means a key minted in one
 * environment cannot even be looked up while another environment is active, so a
 * key presented on the wrong host simply doesn't resolve. Only the hash is stored.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $name
 * @property string $prefix
 * @property string $token_hash
 * @property list<string> $scopes
 * @property Carbon|null $last_used_at
 * @property Carbon|null $expires_at
 * @property Carbon|null $revoked_at
 */
final class EnvironmentApiKey extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'environment_api_keys';

    protected $guarded = [];

    /** @var list<string> */
    protected $hidden = ['token_hash'];

    /** Usable only while neither revoked nor past its expiry. */
    public function isActive(): bool
    {
        if ($this->revoked_at !== null) {
            return false;
        }

        return $this->expires_at === null || $this->expires_at->isFuture();
    }

    /** Whether this key carries the given scope (deny-by-default). */
    public function can(EnvironmentApiScope $scope): bool
    {
        return in_array($scope->value, $this->scopes, true);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }
}
