<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment as EnvironmentContract;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\EnvironmentResolutionCache;
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
 * @property EnvironmentStatus $status
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
            'status' => EnvironmentStatus::class,
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

        // The bulk clear above is a mass update and fires no model events, so the
        // demoted rows' cached default would otherwise survive. Nothing else needs
        // dropping: forgetEnvironment() also forgets the cached default.
        app(EnvironmentResolutionCache::class)->forgetEnvironment($this->id);
    }

    /**
     * Keep {@see EnvironmentResolutionCache} honest.
     *
     * Every write that could change how a host resolves — a create, a rename, a
     * custom-domain move, a suspension — passes through here, so the cache is
     * invalidated at the one place that cannot be forgotten by a new call site.
     *
     * The ORIGINAL domain is forgotten as well as the current one: moving a custom
     * domain from `a.example.com` to `b.example.com` must stop serving the old host,
     * and only the model knows what the old value was.
     */
    protected static function booted(): void
    {
        static::saved(function (self $environment): void {
            $cache = app(EnvironmentResolutionCache::class);

            $cache->forgetEnvironment($environment->id);
            $cache->forgetHost($environment->domain);
            $cache->forgetHost(is_string($environment->getOriginal('domain')) ? $environment->getOriginal('domain') : null);

            // A SLUG-derived host is enumerable too — `config('cbox-id.environments.base_domains')`
            // is exactly the list to enumerate against — so a rename invalidates both the
            // host it used to answer on and the one it answers on now. Without this the old
            // subdomain kept resolving for a full TTL after a rename, which is the one
            // staleness window this cache had left.
            foreach ([$environment->getOriginal('slug'), $environment->slug] as $slug) {
                if (is_string($slug) && $slug !== '') {
                    foreach ($cache->baseDomains() as $base) {
                        $cache->forgetHost($slug.'.'.$base);
                    }
                }
            }
        });

        static::deleted(function (self $environment): void {
            $cache = app(EnvironmentResolutionCache::class);

            $cache->forgetEnvironment($environment->id);
            $cache->forgetHost($environment->domain);

            foreach ($cache->baseDomains() as $base) {
                $cache->forgetHost($environment->slug.'.'.$base);
            }
        });
    }
}
