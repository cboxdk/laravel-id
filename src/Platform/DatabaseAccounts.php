<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Models\Account;

/**
 * Eloquent-backed accounts. No environment scope is ever applied — an account
 * owns environments, it does not live inside one — so these queries are global.
 */
final class DatabaseAccounts implements Accounts
{
    public function find(string $id): ?Account
    {
        return Account::query()->whereKey($id)->first();
    }

    public function create(string $name, int $environmentLimit = 2): Account
    {
        return Account::query()->create([
            'name' => $name,
            'status' => 'active',
            'environment_limit' => max(1, $environmentLimit),
        ]);
    }

    public function remainingEnvironments(Account $account): int
    {
        $used = Environment::query()->where('account_id', $account->id)->count();

        return max(0, $account->environment_limit - $used);
    }
}
