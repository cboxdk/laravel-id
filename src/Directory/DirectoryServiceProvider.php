<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Illuminate\Support\ServiceProvider;

final class DirectoryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Directories::class, DirectoryService::class);
        $this->app->singleton(DirectorySync::class, DatabaseDirectorySync::class);
    }
}
