<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use Illuminate\Support\ServiceProvider;

final class CryptoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(SecretBox::class, static function (): SecretBox {
            $configured = config('cbox-id.crypto.key');

            $decoded = is_string($configured) && $configured !== ''
                ? base64_decode($configured, true)
                : false;

            if ($decoded === false) {
                throw CryptoConfigurationException::missingKey();
            }

            return new LibsodiumSecretBox($decoded);
        });

        $this->app->singleton(KeyManager::class, DatabaseKeyManager::class);
        $this->app->singleton(TokenSigner::class, JwtTokenSigner::class);
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../../../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../../config/cbox-id.php' => config_path('cbox-id.php'),
            ], 'cbox-id-config');

            $this->publishes([
                __DIR__.'/../../../database/migrations' => database_path('migrations'),
            ], 'cbox-id-migrations');
        }
    }
}
