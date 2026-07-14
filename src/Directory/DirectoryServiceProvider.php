<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Illuminate\Support\ServiceProvider;

final class DirectoryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Directories::class, DirectoryService::class);
        $this->app->singleton(DirectorySync::class, DatabaseDirectorySync::class);
        $this->app->singleton(DirectoryUsers::class, DatabaseDirectoryUsers::class);
        $this->app->singleton(DirectoryGroups::class, DatabaseDirectoryGroups::class);
    }
}
