<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Console\RewrapSecretsCommand;
use Cbox\Id\Kernel\Crypto\Console\RotateKeysCommand;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\MasterKeyRing;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\SecretRewrapper;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\ValueObjects\MasterKeySet;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Cbox\Id\Support\PackageConfigMerger;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class CryptoServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(SecretBox::class, static fn (): SecretBox => new LibsodiumSecretBox(self::configuredKeys()));

        // NOT a singleton, deliberately: it answers from whatever SecretBox is bound NOW.
        // The installer and the tests swap the key at runtime and forget the SecretBox
        // instance; a separately cached keyring would keep describing the old key, and
        // the rewrap would then "finish" against a key nothing seals with any more. A
        // host that replaced the SecretBox with one that is not a keyring (a KMS) still
        // gets a working rewrap of the package's own envelopes from the configured keys.
        $this->app->bind(MasterKeyRing::class, static function (Application $app): MasterKeyRing {
            $box = $app->make(SecretBox::class);

            return $box instanceof MasterKeyRing ? $box : new LibsodiumSecretBox(self::configuredKeys());
        });

        $this->app->singleton(SealedColumns::class, SealedColumnRegistry::class);
        $this->app->bind(SecretRewrapper::class, DatabaseSecretRewrapper::class);

        // The kernel's own sealed column. Every other module registers its own.
        $this->callAfterResolving(SealedColumns::class, static function (SealedColumns $columns): void {
            $columns->register(new SealedColumn('signing_keys', 'private_key_encrypted', 'cbox-id:signing-key:', contextColumn: 'kid'));
        });

        $this->app->singleton(KeyManager::class, DatabaseKeyManager::class);
        $this->app->singleton(TokenSigner::class, JwtTokenSigner::class);
    }

    /**
     * The configured keyring: `cbox-id.crypto.key` is the current key (an optional
     * leading `base64:` prefix — Laravel's own convention for `APP_KEY` — is accepted),
     * and `cbox-id.crypto.previous_keys` the ones kept only to open older secrets.
     */
    private static function configuredKeys(): MasterKeySet
    {
        return MasterKeySet::fromConfig(config('cbox-id.crypto.key'), config('cbox-id.crypto.previous_keys'));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../../config/cbox-id.php' => config_path('cbox-id.php'),
            ], 'cbox-id-config');

            $this->commands([RotateKeysCommand::class, RewrapSecretsCommand::class]);
        }
    }
}
