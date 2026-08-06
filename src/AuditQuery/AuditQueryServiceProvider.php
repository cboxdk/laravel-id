<?php

declare(strict_types=1);

namespace Cbox\Id\AuditQuery;

use Cbox\Id\AuditQuery\Contracts\AuditReader;
use Illuminate\Support\ServiceProvider;

class AuditQueryServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(AuditReader::class, DatabaseAuditReader::class);
    }
}
