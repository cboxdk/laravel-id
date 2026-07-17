<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

final class WebhookServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(WebhookRegistry::class, DatabaseWebhookRegistry::class);
        $this->app->singleton(WebhookDispatcher::class, HttpWebhookDispatcher::class);
    }

    public function boot(): void
    {
        // Fan every delivered domain event out to subscribed webhook endpoints. The
        // event's organization id is folded into the payload so a receiver always
        // knows which tenant an event belongs to — domain events keep org as a
        // separate field, but an outbound consumer only sees the JSON body.
        Event::listen(EventDelivered::class, function (EventDelivered $delivered): void {
            $payload = $delivered->event->payload;
            $organizationId = $delivered->event->organization_id;

            if ($organizationId !== null && ! array_key_exists('organization_id', $payload)) {
                $payload['organization_id'] = $organizationId;
            }

            $this->app->make(WebhookDispatcher::class)->dispatch(
                $delivered->event->type,
                $payload,
                $organizationId,
            );
        });

        // Redeliver due failures on a schedule, so a transient outage recovers
        // without a caller wiring the retry loop by hand. Opt out to drive
        // retryPending() yourself.
        if (config('cbox-id.webhooks.schedule_retries', true) === true) {
            $this->callAfterResolving(Schedule::class, function (Schedule $schedule): void {
                $schedule->call(fn () => $this->app->make(WebhookDispatcher::class)->retryPending())
                    ->everyMinute()
                    ->name('cbox-id:webhooks:retry')
                    ->withoutOverlapping();
            });
        }
    }
}
