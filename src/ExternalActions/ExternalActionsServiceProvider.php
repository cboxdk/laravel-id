<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions;

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Contracts\ActionRegistry;
use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Cbox\Id\Support\PackageConfigMerger;
use Illuminate\Support\ServiceProvider;

class ExternalActionsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // An inline hook's signing secret (ExternalActionEndpoint::secretContext()).
        // Registered so a master-key rotation (`cbox-id:crypto:rewrap`) re-seals it.
        $this->callAfterResolving(SealedColumns::class, static function (SealedColumns $columns): void {
            $columns->register(new SealedColumn('external_action_endpoints', 'secret_encrypted', 'cbox-id:external-action:'));
        });

        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(ActionRegistry::class, ConfigActionRegistry::class);
        $this->app->singleton(ExternalActions::class, DatabaseExternalActions::class);
        $this->app->singleton(ActionTransport::class, HttpActionTransport::class);
        $this->app->singleton(ActionPipeline::class, DefaultActionPipeline::class);
    }
}
