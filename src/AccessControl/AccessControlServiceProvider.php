<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Illuminate\Support\ServiceProvider;

final class AccessControlServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Roles::class, RoleService::class);
        $this->app->singleton(AccessChecker::class, HierarchyAwareAccessChecker::class);
        $this->app->singleton(AppManifests::class, ManifestSyncService::class);
    }
}
