<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes;

use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Cbox\Id\Pipes\Console\RefreshPipeConnectionsCommand;
use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\Contracts\Pipes;
use Cbox\Id\Pipes\Contracts\PipeTokens;
use Cbox\Id\Pipes\Erasure\PipeConnectionsErasureStep;
use Cbox\Id\Support\PackageConfigMerger;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

/**
 * Pipes: people connect their own third-party accounts (GitHub, Google, Slack, …) and the
 * environment's authorised apps lease fresh access tokens for them.
 *
 * Built ON the token vault rather than beside it: every token is a user-owned vault
 * secret, so it is sealed, audited, rewrapped on a master-key rotation and erased with the
 * person by the machinery that already does those things.
 */
class PipesServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(Pipes::class, DatabasePipes::class);
        $this->app->singleton(PipeConnections::class, DatabasePipeConnections::class);
        $this->app->singleton(PipeTokens::class, DatabasePipeTokens::class);

        // The pipe's OAuth client secret, bound to its row (Pipe::secretContext()), so a
        // master-key rotation (`cbox-id:crypto:rewrap`) re-seals it with everything else.
        // The person's tokens are vault secrets and are already covered there.
        $this->callAfterResolving(SealedColumns::class, static function (SealedColumns $columns): void {
            $columns->register(new SealedColumn('pipes', 'client_secret_encrypted', 'cbox-id:pipe-client-secret:'));
        });

        $this->callAfterResolving(ErasureSteps::class, static function (ErasureSteps $steps, Application $app): void {
            $steps->register($app->make(PipeConnectionsErasureStep::class));
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([RefreshPipeConnectionsCommand::class]);
        }

        // Every five minutes: HubSpot's tokens live thirty, so a ten-minute look-ahead
        // swept every five refreshes each one at least once before it dies.
        if (config('cbox-id.pipes.schedule', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->command(RefreshPipeConnectionsCommand::class)
                    ->everyFiveMinutes()
                    ->name('cbox-id:pipes:refresh')
                    ->withoutOverlapping();
            });
        }
    }
}
