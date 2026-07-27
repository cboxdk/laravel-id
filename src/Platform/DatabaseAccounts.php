<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
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
    public function __construct(private readonly AuditLog $audit) {}

    public function find(string $id): ?Account
    {
        return Account::query()->whereKey($id)->first();
    }

    public function rename(string $id, string $name): void
    {
        Account::query()->whereKey($id)->update(['name' => $name]);
    }

    public function suspend(string $id, string $actorId): void
    {
        $this->transitionStatus($id, AccountStatus::Suspended, 'account.suspended', $actorId);
    }

    public function reactivate(string $id, string $actorId): void
    {
        $this->transitionStatus($id, AccountStatus::Active, 'account.reactivated', $actorId);
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
     * Write the status, invalidate the tenant's resolution cache, and append the
     * audit entry — in that order, as one operation the caller cannot half-perform.
     *
     * The audit entry is recorded only when the status ACTUALLY changed. Both verbs
     * are documented idempotent, and a re-suspension that appends a second
     * `account.suspended` would leave the trail unable to answer when the account was
     * suspended and by whom.
     *
     * The account lives above the tenancy boundary, so the entry goes on the SYSTEM
     * chain (`organizationId: null`), like every other platform-plane action.
     */
    private function transitionStatus(string $id, AccountStatus $status, string $action, string $actorId): void
    {
        $account = Account::query()->whereKey($id)->first();

        if ($account === null || $account->status === $status) {
            return;
        }

        $account->forceFill(['status' => $status])->save();

        $this->forgetResolutionCache($id);

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::Operator,
            actorId: $actorId,
            targetType: 'account',
            targetId: $account->id,
            context: ['status' => $status->value],
        ));
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
