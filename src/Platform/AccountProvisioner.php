<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Exceptions\EnvironmentLimitReached;
use Cbox\Id\Platform\Models\Account;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Cbox\Id\Platform\ValueObjects\ProvisionedAccount;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Self-serve provisioning of a whole account — the customer's workspace and their
 * first environment (their own IdP). This is a PLATFORM-level operation: an
 * account owns environments but is not itself inside one, so it runs above any
 * tenant scope.
 *
 * The account plane never seeds the end-user plane: a provisioned environment is
 * born EMPTY (no organization, no subject). The account member administers it
 * from the root console; organizations and their users are created later, inside
 * the environment. That one-way layering — account → environment → organization →
 * user, never the reverse — is what keeps IdP-creation a root capability that
 * never recurses into a customer's environment.
 *
 * Everything is one transaction: a failed member/environment step never leaves a
 * half-born account or a routable-but-orphaned environment.
 */
final class AccountProvisioner
{
    public function __construct(
        private readonly EnvironmentContext $context,
        private readonly KeyManager $keys,
        private readonly Accounts $accounts,
        private readonly AccountMembers $members,
    ) {}

    public function provision(AccountBlueprint $blueprint): ProvisionedAccount
    {
        return DB::transaction(function () use ($blueprint): ProvisionedAccount {
            $account = $this->accounts->create($blueprint->accountName, $blueprint->environmentLimit);

            $member = $this->members->create(
                $account->id,
                $blueprint->ownerEmail,
                $blueprint->ownerPassword,
                $blueprint->ownerName,
            );

            $environment = $this->createEnvironment($account, $blueprint->environmentName, $blueprint->domain);

            return new ProvisionedAccount($account, $member, $environment);
        });
    }

    /**
     * Stand up an additional environment under an existing account (e.g. adding
     * staging alongside production), respecting the plan's environment allowance.
     *
     * @throws EnvironmentLimitReached
     */
    public function addEnvironment(Account $account, string $name, ?string $domain = null): Environment
    {
        return DB::transaction(function () use ($account, $name, $domain): Environment {
            // Re-check under the row lock so two concurrent adds can't both slip
            // past a limit-of-one.
            $locked = Account::query()->whereKey($account->id)->lockForUpdate()->firstOrFail();

            if ($this->accounts->remainingEnvironments($locked) < 1) {
                throw EnvironmentLimitReached::make($locked->id, $locked->environment_limit);
            }

            return $this->createEnvironment($locked, $name, $domain);
        });
    }

    /**
     * Create an environment owned by the account and warm its signing key so its
     * JWKS/discovery is live the instant it is routable. The environment is left
     * empty of tenants by design.
     */
    private function createEnvironment(Account $account, string $name, ?string $domain): Environment
    {
        $environment = Environment::query()->create([
            'account_id' => $account->id,
            'name' => $name,
            'slug' => $this->uniqueSlug($name),
            'domain' => $domain,
            'status' => 'active',
        ]);

        $this->context->runAs($environment, function (): void {
            $this->keys->activeSigningKey();
        });

        return $environment;
    }

    /** A slug unique across environments (the routing key when no custom domain is set). */
    private function uniqueSlug(string $name): string
    {
        $base = $this->slug($name);
        $slug = $base;
        $suffix = 1;

        while (Environment::query()->where('slug', $slug)->exists()) {
            $slug = $base.'-'.(++$suffix);
        }

        return $slug;
    }

    private function slug(string $value): string
    {
        $slug = Str::slug($value);

        return $slug !== '' ? $slug : 'env-'.Str::lower(Str::random(6));
    }
}
