<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Connectors\GoogleWorkspaceConnector;
use Cbox\Id\Directory\Connectors\MicrosoftEntraConnector;
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Illuminate\Support\ServiceProvider;

class DirectoryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Directories::class, DirectoryService::class);
        $this->app->singleton(DirectorySync::class, DatabaseDirectorySync::class);
        $this->app->singleton(DirectoryUsers::class, DatabaseDirectoryUsers::class);
        $this->app->singleton(DirectoryGroups::class, DatabaseDirectoryGroups::class);

        // API-pull directory connectors (Google Workspace, Microsoft Entra). A host
        // can register more by rebinding this with additional connectors.
        $this->app->singleton(DirectoryConnectors::class, fn (): DirectoryConnectors => new DirectoryConnectors([
            new GoogleWorkspaceConnector,
            new MicrosoftEntraConnector,
        ]));
    }
}
