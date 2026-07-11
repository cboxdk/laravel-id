<?php

declare(strict_types=1);

namespace Cbox\Id;

use Illuminate\Support\ServiceProvider;

/**
 * Root service provider for the Cbox ID platform.
 * Each module registers its bindings via a dedicated module provider booted here.
 */
final class IdServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        //
    }
}
