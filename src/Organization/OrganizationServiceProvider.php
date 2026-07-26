<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Kernel\Usage\Contracts\ReconcilableScopes;
use Cbox\Id\Kernel\Usage\Contracts\SeatCensus;
use Cbox\Id\Organization\Contracts\EnvironmentDomains;
use Cbox\Id\Organization\Contracts\Groups;
use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\ResourceAccess;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Illuminate\Support\ServiceProvider;

class OrganizationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(OrganizationHierarchy::class, ClosureOrganizationHierarchy::class);
        $this->app->singleton(Organizations::class, OrganizationService::class);
        $this->app->singleton(Memberships::class, MembershipService::class);
        $this->app->singleton(Invitations::class, InvitationService::class);
        $this->app->singleton(Groups::class, GroupService::class);
        $this->app->singleton(ResourceAccess::class, ResourceAccessService::class);
        $this->app->singleton(UserApiTokens::class, UserApiTokenService::class);
        $this->app->singleton(EnvironmentResolutionCache::class);

        // Host → environment resolution is 2–3 uncached queries that EVERY request
        // paid before any endpoint logic ran, against a table that changes
        // approximately never. The decorator is the binding, so nothing that depends
        // on the contract has to opt in; set the TTL to 0 to bypass it.
        $this->app->singleton(
            EnvironmentResolver::class,
            fn (): EnvironmentResolver => new CachedEnvironmentResolver(
                $this->app->make(DatabaseEnvironmentResolver::class),
                $this->app->make(EnvironmentResolutionCache::class),
            ),
        );
        $this->app->singleton(IssuerResolver::class, EnvironmentIssuerResolver::class);
        $this->app->singleton(EnvironmentDomains::class, EnvironmentDomainService::class);

        // The Usage kernel reconciles per organization but must not import the
        // Organization model or its membership semantics — it depends on these two
        // contracts, and this module (which owns both) supplies the metered ids and
        // the seat ground truth.
        $this->app->singleton(ReconcilableScopes::class, DatabaseReconcilableScopes::class);
        $this->app->singleton(SeatCensus::class, DatabaseSeatCensus::class);
    }
}
