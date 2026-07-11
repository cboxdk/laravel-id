<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Illuminate\Support\ServiceProvider;

final class AuthorizationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(DatabaseEntitlements::class);
        $this->app->alias(DatabaseEntitlements::class, EntitlementReader::class);
        $this->app->alias(DatabaseEntitlements::class, EntitlementWriter::class);

        $this->app->singleton(RelationshipStore::class, DatabaseRelationshipStore::class);
        $this->app->singleton(PolicyDecisionPoint::class, DefaultPolicyDecisionPoint::class);
    }
}
