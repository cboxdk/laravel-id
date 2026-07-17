<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Contracts\OperatorMfa;
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
            return new DatabasePlatformOperators($app->make(Hasher::class), $app->make(AuditLog::class));
        });

        $this->app->singleton(OperatorMfa::class, function (Application $app): OperatorMfa {
            return new DatabaseOperatorMfa(
                $app->make(TotpAuthenticator::class),
                $app->make(SecretBox::class),
                $app->make(AuditLog::class),
            );
        });

        // The account plane — the customer workspaces that own environments, and
        // the members who administer them from the platform root.
        $this->app->singleton(Accounts::class, DatabaseAccounts::class);

        $this->app->singleton(AccountMembers::class, function (Application $app): AccountMembers {
            return new DatabaseAccountMembers($app->make(Hasher::class));
        });
    }
}
