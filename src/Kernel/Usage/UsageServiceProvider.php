<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage;

use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Usage\Console\ReconcileUsageCommand;
use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\Listeners\RecordUsageOnDomainEvent;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

final class UsageServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(
            UsageMeter::class,
            fn (): DatabaseUsageMeter => new DatabaseUsageMeter($this->enabled()),
        );
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([ReconcileUsageCommand::class]);
        }

        // Auto-meter domain events off the outbox. Skipped entirely when disabled, so
        // a deployment that doesn't want metering pays nothing (no marker writes).
        if (! $this->enabled()) {
            return;
        }

        Event::listen(EventDelivered::class, function (EventDelivered $delivered): void {
            $this->app->make(RecordUsageOnDomainEvent::class)->handle($delivered);
        });
    }

    private function enabled(): bool
    {
        return config('cbox-id.usage.enabled', true) === true;
    }
}
