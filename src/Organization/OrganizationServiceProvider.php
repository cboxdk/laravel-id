<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Cbox\Id\Organization\Contracts\Organizations;
use Illuminate\Support\ServiceProvider;

final class OrganizationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(OrganizationHierarchy::class, ClosureOrganizationHierarchy::class);
        $this->app->singleton(Organizations::class, OrganizationService::class);
        $this->app->singleton(Memberships::class, MembershipService::class);
        $this->app->singleton(Invitations::class, InvitationService::class);
        $this->app->singleton(
            EnvironmentResolver::class,
            DatabaseEnvironmentResolver::class,
        );
        $this->app->singleton(IssuerResolver::class, EnvironmentIssuerResolver::class);
    }
}
