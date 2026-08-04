<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Contracts\WebAuthnVerifier;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Platform\Contracts\AccountApiKeys;
use Cbox\Id\Platform\Contracts\AccountMemberMfa;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Contracts\AccountPasskeys;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Contracts\EnvironmentAdminHandoff;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Contracts\OperatorMfa;
use Cbox\Id\Platform\Contracts\OrganizationProjects;
use Cbox\Id\Platform\Contracts\PlatformOperators;
use Cbox\Id\Platform\Contracts\Projects;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\ServiceProvider;

/**
 * Wires the platform layer — the identities that stand above every environment.
 */
class PlatformServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(PlatformOperators::class, function (Application $app): PlatformOperators {
            return new DatabasePlatformOperators(
                $app->make(Hasher::class),
                $app->make(AuditLog::class),
                $app->make(Subjects::class),
                $app->make(PlatformRoot::class),
            );
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

        // Projects — the IdP-product layer inside an account (billing anchor).
        $this->app->singleton(Projects::class, DatabaseProjects::class);

        // The same products read from the organization side, since an account IS an
        // organization. A second binding of the same stateless class rather than an
        // alias of the one above: a host that swaps `Projects` for its own
        // implementation must not silently lose this capability along with it.
        $this->app->singleton(OrganizationProjects::class, DatabaseProjects::class);

        $this->app->singleton(AccountMembers::class, function (Application $app): AccountMembers {
            return new DatabaseAccountMembers(
                $app->make(Hasher::class),
                // Account members authenticate as subjects in the platform-root
                // environment — one identity stack, not two.
                $app->make(Subjects::class),
                $app->make(Memberships::class),
                $app->make(PlatformRoot::class),
                // A credential write ends every session opened with the credential it
                // replaced, and a member's sessions are ordinary subject sessions.
                $app->make(SessionManager::class),
            );
        });

        $this->app->singleton(AccountApiKeys::class, DatabaseAccountApiKeys::class);

        $this->app->singleton(EnvironmentApiKeys::class, DatabaseEnvironmentApiKeys::class);

        // The signed bridge that lets an account member administer a tenant
        // environment without a second login (and without being a subject there).
        $this->app->singleton(EnvironmentAdminHandoff::class, function (Application $app): EnvironmentAdminHandoff {
            return new SignedEnvironmentAdminHandoff(
                $app->make(TokenSigner::class),
                $app->make(CacheRepository::class),
            );
        });

        $this->app->singleton(AccountMemberMfa::class, function (Application $app): AccountMemberMfa {
            return new DatabaseAccountMemberMfa(
                $app->make(TotpAuthenticator::class),
                $app->make(SecretBox::class),
                $app->make(AuditLog::class),
            );
        });

        $this->app->singleton(AccountPasskeys::class, function (Application $app): AccountPasskeys {
            return new DatabaseAccountPasskeys(
                $app->make(WebAuthnVerifier::class),
                $app->make(AuditLog::class),
            );
        });
    }
}
