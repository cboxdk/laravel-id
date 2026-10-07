<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault;

use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Support\PackageConfigMerger;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Erasure\VaultSecretsErasureStep;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class TokenVaultServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // This module's share of a GDPR erasure (see SubjectEraser): the personal data it
        // owns is erased by the module that owns it.
        $this->callAfterResolving(ErasureSteps::class, static function (ErasureSteps $steps, Application $app): void {
            $steps->register($app->make(VaultSecretsErasureStep::class));
        });

        // The vaulted downstream credential, bound to its row (VaultSecret::secretContext()).
        // Registered so a master-key rotation (`cbox-id:crypto:rewrap`) re-seals it.
        $this->callAfterResolving(SealedColumns::class, static function (SealedColumns $columns): void {
            $columns->register(new SealedColumn('vault_secrets', 'secret_encrypted', 'cbox-id:vault-secret:'));
        });

        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../../config/cbox-id.php', 'cbox-id');

        $this->app->singleton(SecretVault::class, function (Application $app): SecretVault {
            return new DatabaseSecretVault(
                $app->make(SecretBox::class),
                $app->make(AuditLog::class),
                $this->intConfig('cbox-id.token_vault.default_lease_ttl_seconds', 300),
                $app->make(EventBus::class),
            );
        });
    }

    private function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }
}
