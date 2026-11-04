<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties;

use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\UserProperties\Contracts\PropertyNamespaces;
use Cbox\Id\UserProperties\Contracts\UserProperties;
use Cbox\Id\Webhooks\Contracts\WebhookDeliveryPolicy;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class UserPropertiesServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(UserProperties::class, DatabaseUserProperties::class);
        $this->app->singleton(PropertyNamespaces::class, DatabasePropertyNamespaces::class);
        $this->app->singleton(WebhookDeliveryPolicy::class, PropertyWebhookPolicy::class);
        $this->callAfterResolving(ErasureSteps::class, static function (ErasureSteps $steps, Application $app): void {
            $steps->register($app->make(PropertiesErasureStep::class));
        });
    }
}
