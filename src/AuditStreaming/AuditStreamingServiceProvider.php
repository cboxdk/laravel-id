<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming;

use Cbox\Id\AuditStreaming\Console\PumpAuditStreamsCommand;
use Cbox\Id\AuditStreaming\Contracts\SiemEventMapper;
use Cbox\Id\AuditStreaming\Jobs\PumpAuditStream;
use Cbox\Id\AuditStreaming\Models\AuditStream;
use Cbox\Id\AuditStreaming\Models\AuditStreamDelivery;
use Cbox\Id\AuditStreaming\Support\DefaultSiemEventMapper;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Contracts\StreamDispatcher;
use Cbox\LaravelSiem\LaravelSiemServiceProvider;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use RuntimeException;

/**
 * Composes cboxdk/laravel-siem's delivery engine into the platform as an
 * ENVIRONMENT-ISOLATED audit-streaming binding.
 *
 * The whole isolation strategy is three config lines plus one decorator:
 *  - point the engine's swappable models at env-owned subclasses, so every
 *    config/list/dispatch/pump path inherits the hard environment scope;
 *  - disable the engine's own scheduler — laravel-id owns SIEM scheduling, because
 *    a worker with no ambient environment must reconstruct one per stream
 *    ({@see PumpAuditStream});
 *  - decorate {@see AuditLog} so every recorded entry is mirrored to the
 *    environment's streams inside the same transaction (transactional outbox).
 */
class AuditStreamingServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Wire the delivery engine (config, migrations, registry, dispatcher, sink).
        $this->app->register(LaravelSiemServiceProvider::class);

        // Swap the engine's models for env-owned subclasses, so the hard
        // environment scope constrains every read/list/dispatch/pump for free.
        $config = $this->app->make(Repository::class);
        $config->set('siem.models.log_stream', AuditStream::class);
        $config->set('siem.models.stream_delivery', AuditStreamDelivery::class);

        // laravel-id owns scheduling: the engine's scheduler would enumerate and
        // pump streams with no ambient environment (deny-by-default), so disable it
        // and drive delivery through PumpAuditStreamsCommand + PumpAuditStream.
        $config->set('siem.schedule.enabled', false);

        $this->app->singleton(SiemEventMapper::class, DefaultSiemEventMapper::class);

        // Decorate the audit log. app->extend composes with any host decorator
        // (e.g. impersonation attribution): whatever inner AuditLog exists is
        // wrapped, and this remains wrappable in turn.
        $this->app->extend(AuditLog::class, function (AuditLog $inner, Application $app): AuditLog {
            return new StreamingAuditLog(
                $inner,
                $app->make(LogStreams::class),
                $app->make(StreamDispatcher::class),
                $app->make(SiemEventMapper::class),
            );
        });
    }

    public function boot(): void
    {
        $this->assertEnvironmentScopedModels();

        if ($this->app->runningInConsole()) {
            $this->commands([PumpAuditStreamsCommand::class]);
        }

        $this->registerSchedule();
    }

    /**
     * Fail LOUD, not silent, if the engine models are ever not the env-owned
     * subclasses. register() forces them, so this normally passes; it exists to turn
     * a future regression (a provider-ordering change, a config:cache that captured a
     * pre-force value, a host that repointed them) into a hard boot failure. The
     * engine's own resolver already rejects a set-but-invalid class, but it accepts
     * the valid-yet-UNSCOPED base LogStream/StreamDelivery — which for this binding
     * would silently stream across environments. Only the exact env-owned subclasses
     * are acceptable here, so this is the guard the engine cannot provide.
     */
    private function assertEnvironmentScopedModels(): void
    {
        $stream = config('siem.models.log_stream');
        $delivery = config('siem.models.stream_delivery');

        if ($stream === AuditStream::class && $delivery === AuditStreamDelivery::class) {
            return;
        }

        throw new RuntimeException(sprintf(
            'Audit-streaming environment isolation requires the engine models to be '
            .'the env-owned subclasses (%s / %s), but they are [%s / %s]. Refusing to '
            .'boot: a non-env-owned model would stream audit events across environments.',
            AuditStream::class,
            AuditStreamDelivery::class,
            is_string($stream) ? $stream : get_debug_type($stream),
            is_string($delivery) ? $delivery : get_debug_type($delivery),
        ));
    }

    /**
     * Mirror the Webhooks module's schedule wiring: dispatch a per-stream pump job
     * for every enabled stream in every environment, once a minute. Opt out to
     * drive PumpAuditStreamsCommand yourself.
     */
    private function registerSchedule(): void
    {
        if (config('cbox-id.audit_streaming.schedule', true) !== true) {
            return;
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
            $schedule->command(PumpAuditStreamsCommand::class)
                ->everyMinute()
                ->name('cbox-id:audit-streams:pump')
                ->withoutOverlapping();
        });
    }
}
