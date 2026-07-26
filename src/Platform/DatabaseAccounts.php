<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Organization\EnvironmentResolutionCache;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Enums\AccountStatus;
use Cbox\Id\Platform\Models\Account;

/**
 * Eloquent-backed accounts. No environment scope is ever applied — an account
 * owns environments, it does not live inside one — so these queries are global.
 */
class DatabaseAccounts implements Accounts
{
    public function find(string $id): ?Account
    {
        return Account::query()->whereKey($id)->first();
    }

    public function rename(string $id, string $name): void
    {
        Account::query()->whereKey($id)->update(['name' => $name]);
    }

    public function suspend(string $id): void
    {
        Account::query()->whereKey($id)->update(['status' => AccountStatus::Suspended]);

        $this->forgetResolutionCache($id);
    }

    public function reactivate(string $id): void
    {
        Account::query()->whereKey($id)->update(['status' => AccountStatus::Active]);

        $this->forgetResolutionCache($id);
    }

    public function create(string $name, int $environmentLimit = 2): Account
    {
        return Account::query()->create([
            'name' => $name,
            'status' => AccountStatus::Active,
            'environment_limit' => max(1, $environmentLimit),
        ]);
    }

    public function remainingEnvironments(Account $account): int
    {
        $used = Environment::query()->where('account_id', $account->id)->count();

        return max(0, $account->environment_limit - $used);
    }

    /**
     * Suspending an account is the platform's off-switch for the whole tenant: its
     * environments must stop serving auth on the NEXT request, not when a cache TTL
     * happens to lapse.
     *
     * The environments themselves are untouched by the status write (the liveness
     * gate reads `accounts` separately), so their own model events do not fire and
     * the invalidation has to be explicit here. Dropping each environment's resolved
     * entry is enough — the host mappings survive, miss on the environment entry and
     * fall through to a full live resolution, which now refuses.
     */
    private function forgetResolutionCache(string $accountId): void
    {
        $cache = app(EnvironmentResolutionCache::class);

        /** @var list<string> $environmentIds */
        $environmentIds = Environment::query()->where('account_id', $accountId)->pluck('id')->all();

        foreach ($environmentIds as $environmentId) {
            $cache->forgetEnvironment($environmentId);
        }
    }
}
