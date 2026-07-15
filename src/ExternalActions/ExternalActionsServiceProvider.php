<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Contracts\ActionRegistry;
use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Illuminate\Support\ServiceProvider;

final class ExternalActionsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(ActionRegistry::class, ConfigActionRegistry::class);
        $this->app->singleton(ExternalActions::class, DatabaseExternalActions::class);
        $this->app->singleton(ActionTransport::class, HttpActionTransport::class);
        $this->app->singleton(ActionPipeline::class, DefaultActionPipeline::class);
    }
}
