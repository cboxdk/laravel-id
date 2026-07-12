<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks;

use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
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
        // Fan every delivered domain event out to subscribed webhook endpoints.
        Event::listen(EventDelivered::class, function (EventDelivered $delivered): void {
            $this->app->make(WebhookDispatcher::class)->dispatch(
                $delivered->event->type,
                $delivered->event->payload,
                $delivered->event->organization_id,
            );
        });
    }
}
