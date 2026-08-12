<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Platform\Contracts\EnvironmentAdminHandoff;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Contracts\OperatorMfa;
use Cbox\Id\Platform\Contracts\OrganizationApiKeys;
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
        // SHARED, or the memo inside it is not a memo.
        //
        // `PlatformRoot::model()` memoises the root environment for the request and says
        // so — "an account-plane page paid this five times over" — but the memo lives on
        // the instance, and the idiom everywhere in this platform is
        // `app(PlatformRoot::class)->run(...)`. Unbound, every one of those calls built a
        // fresh object and re-queried: one console page render was measured making 407
        // `where is_default` selects, all of them the same question.
        //
        // `scoped` rather than `singleton` because the answer is request-bounded by
        // design: an octane worker that kept it would serve a stale root across a
        // migration, which is the case {@see RequestLifetime} exists to bound.
        $this->app->scoped(PlatformRoot::class);

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

        // Projects — the IdP-product layer a customer owns (the billing anchor).
        $this->app->singleton(Projects::class, DatabaseProjects::class);

        // The same products, read from the organization side. A second binding of the
        // same stateless class rather than an alias: a host that swaps `Projects` for its
        // own implementation must not silently lose this capability along with it.
        $this->app->singleton(OrganizationProjects::class, DatabaseProjects::class);

        // The management plane's machine credential. There is no `Accounts` or
        // `AccountMembers` binding beside it any more: a customer IS an organization
        // ({@see \Cbox\Id\Organization\Contracts\Organizations}) and a member of one IS
        // a membership ({@see \Cbox\Id\Organization\Contracts\Memberships}), so the
        // container no longer offers a second way to ask either question.
        $this->app->singleton(OrganizationApiKeys::class, DatabaseOrganizationApiKeys::class);

        $this->app->singleton(EnvironmentApiKeys::class, DatabaseEnvironmentApiKeys::class);

        // The signed bridge that lets an account member administer a tenant
        // environment without a second login (and without being a subject there).
        $this->app->singleton(EnvironmentAdminHandoff::class, function (Application $app): EnvironmentAdminHandoff {
            return new SignedEnvironmentAdminHandoff(
                $app->make(TokenSigner::class),
                $app->make(CacheRepository::class),
            );
        });
    }
}
