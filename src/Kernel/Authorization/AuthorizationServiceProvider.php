<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Illuminate\Support\ServiceProvider;

final class AuthorizationServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(DatabaseEntitlements::class);
        $this->app->alias(DatabaseEntitlements::class, EntitlementReader::class);
        $this->app->alias(DatabaseEntitlements::class, EntitlementWriter::class);
    }
}
