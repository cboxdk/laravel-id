<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\OAuthServer\Enums\SupportActorKind;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Somebody acting AS a customer's user, in one organization and one app, for a stated
 * reason and a bounded time. The row is the authority every code and token minted for it
 * is checked against.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $actor_id
 * @property SupportActorKind $actor_kind
 * @property string $target_user_id
 * @property string $organization_id
 * @property string $client_id
 * @property array<int, string> $scopes
 * @property string $reason
 * @property Carbon $expires_at
 * @property Carbon|null $ended_at
 * @property string|null $ended_by
 * @property Carbon|null $created_at
 */
class SupportSession extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'support_sessions';

    protected $guarded = [];

    public function isActive(): bool
    {
        return $this->ended_at === null && $this->expires_at->isFuture();
    }

    /**
     * Not ended and not expired — in the WHERE clause, so a read of "the active session"
     * can never return one that is not.
     *
     * @param  Builder<self>  $query
     */
    public function scopeActive(Builder $query): void
    {
        $query->whereNull($query->qualifyColumn('ended_at'))
            ->where($query->qualifyColumn('expires_at'), '>', now());
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'actor_kind' => SupportActorKind::class,
            'scopes' => 'array',
            'expires_at' => 'datetime',
            'ended_at' => 'datetime',
        ];
    }
}
