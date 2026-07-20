<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Console\RotateKeysCommand;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use Illuminate\Support\ServiceProvider;

class CryptoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(SecretBox::class, static function (): SecretBox {
            $configured = config('cbox-id.crypto.key');

            $decoded = is_string($configured) ? self::decodeKey($configured) : false;

            if ($decoded === false) {
                throw CryptoConfigurationException::missingKey();
            }

            return new LibsodiumSecretBox($decoded);
        });

        $this->app->singleton(KeyManager::class, DatabaseKeyManager::class);
        $this->app->singleton(TokenSigner::class, JwtTokenSigner::class);
    }

    /**
     * Decode the configured master key. An optional leading `base64:` prefix —
     * Laravel's own convention for `APP_KEY` and friends, which operators reach
     * for by muscle memory — is stripped before the strict decode. Returns false
     * for an empty or genuinely invalid value, so the caller raises the missing-key
     * exception unchanged.
     */
    private static function decodeKey(string $configured): string|false
    {
        if ($configured === '') {
            return false;
        }

        if (str_starts_with($configured, 'base64:')) {
            $configured = substr($configured, 7);
        }

        return base64_decode($configured, true);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../../config/cbox-id.php' => config_path('cbox-id.php'),
            ], 'cbox-id-config');

            $this->commands([RotateKeysCommand::class]);
        }
    }
}
