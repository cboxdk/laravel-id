<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

final class AuthorizationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Reads and writes go through the hot-path cache: every check is served
        // from cache, and a write invalidates instantly (version bump) so billing/
        // entitlement changes propagate on the next request — no token rotation.
        $this->app->singleton(DatabaseEntitlements::class);
        $this->app->singleton(CachedEntitlements::class, fn (Application $app): CachedEntitlements => new CachedEntitlements(
            $app->make(DatabaseEntitlements::class),
            $app->make(Cache::class),
        ));
        $this->app->alias(CachedEntitlements::class, EntitlementReader::class);
        $this->app->alias(CachedEntitlements::class, EntitlementWriter::class);

        $this->app->singleton(RelationshipStore::class, DatabaseRelationshipStore::class);
        $this->app->singleton(PolicyDecisionPoint::class, DefaultPolicyDecisionPoint::class);
    }
}
