<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class TokenVaultServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(SecretVault::class, function (Application $app): SecretVault {
            return new DatabaseSecretVault(
                $app->make(SecretBox::class),
                $app->make(AuditLog::class),
                $app->make(EnvironmentContext::class),
                $this->intConfig('cbox-id.token_vault.default_lease_ttl_seconds', 300),
            );
        });
    }

    private function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
