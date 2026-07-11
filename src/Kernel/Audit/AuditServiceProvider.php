<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Illuminate\Support\ServiceProvider;

final class AuditServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuditLog::class, DatabaseAuditLog::class);
    }
}
