<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Platform\Contracts\PlatformOperators;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\ServiceProvider;

/**
 * Wires the platform layer — the identities that stand above every environment.
 */
final class PlatformServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(PlatformOperators::class, function (Application $app): PlatformOperators {
            return new DatabasePlatformOperators($app->make(Hasher::class));
        });
    }
}
