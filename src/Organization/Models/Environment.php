<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment as EnvironmentContract;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * The environment — the hard identity/tenancy boundary. It is NOT itself
 * environment-owned (it is the boundary); provisioning it happens outside any
 * environment scope. Its id is the environment key stored on every owned row.
 *
 * @property string $id
 * @property string|null $account_id
 * @property string $name
 * @property string $slug
 * @property EnvironmentType $type
 * @property string|null $domain
 * @property Carbon|null $domain_verified_at
 * @property string $status
 * @property bool $is_default
 * @property array<string, mixed> $settings
 */
class Environment extends Model implements EnvironmentContract
{
    use HasUlids;

    protected $table = 'environments';

    protected $guarded = [];

    /** A development/test realm: relaxed rules, no real outbound email, badged. */
    public function isSandbox(): bool
    {
        return $this->type === EnvironmentType::Sandbox;
    }

    protected function casts(): array
    {
        return [
            'type' => EnvironmentType::class,
            'is_default' => 'boolean',
            'settings' => 'array',
            'domain_verified_at' => 'datetime',
        ];
    }

    public function environmentKey(): string
    {
        return $this->id;
    }

    /**
     * Mark this environment as the single-tenant / host-less default, clearing
     * the flag on every other row in the same transaction so exactly one default
     * ever exists. This is the source of truth for the fallback plane — no env
     * var required, so it holds across a horizontally-scaled, stateless
     * deployment (k8s with no writable .env).
     */
    public function makeDefault(): void
    {
        DB::transaction(function (): void {
            static::query()
                ->where('is_default', true)
                ->whereKeyNot($this->getKey())
                ->update(['is_default' => false]);

            $this->forceFill(['is_default' => true])->save();
        });
    }
}
