<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Contracts\Projects;
use Cbox\Id\Platform\Exceptions\AccountSuspended;
use Cbox\Id\Platform\Exceptions\EnvironmentLimitReached;
use Cbox\Id\Platform\Exceptions\ProjectSuspended;
use Cbox\Id\Platform\Models\Account;
use Cbox\Id\Platform\Models\Project;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Cbox\Id\Platform\ValueObjects\ProvisionedAccount;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Self-serve provisioning of a whole account — the customer's workspace, their first
 * project (their first IdP product) and that project's first environment. This is a
 * PLATFORM-level operation: an account owns projects which own environments, but the
 * account is not itself inside one, so it runs above any tenant scope.
 *
 * The layering is Account → Project → Environment → Organization → Subject, one way,
 * never the reverse: the account plane never seeds the end-user plane, so a
 * provisioned environment is born EMPTY. Billing lives on the PROJECT, so one account
 * can own several independently-billed IdP products (Clerk's "Applications").
 *
 * Everything is one transaction: a failed step never leaves a half-born account or a
 * routable-but-orphaned environment.
 */
final class AccountProvisioner
{
    public function __construct(
        private readonly EnvironmentContext $context,
        private readonly KeyManager $keys,
        private readonly Accounts $accounts,
        private readonly AccountMembers $members,
        private readonly Projects $projects,
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

            // The account's first IdP product. Named after the account by default;
            // its plan allowance is the blueprint's environment limit (billing lives
            // on the project, so this is where the allowance belongs).
            $project = $this->projects->create($account->id, $blueprint->accountName, $blueprint->environmentLimit);

            // The routing slug (subdomain) derives from the PROJECT's identity, not
            // the stage name — so "Acme" gets acme.example, not a generic
            // "production.example" every customer would collide on.
            $environment = $this->createEnvironment(
                $project,
                $blueprint->environmentName,
                $blueprint->domain,
                slugSeed: $project->name,
                type: EnvironmentType::Production,
            );

            return new ProvisionedAccount($account, $member, $project, $environment);
        });
    }

    /**
     * Stand up an additional IdP product (project) under an existing account — a
     * separately-billed product alongside the first, no second login required.
     */
    public function addProject(Account $account, string $name, ?int $environmentLimit = null): Project
    {
        return DB::transaction(function () use ($account, $name, $environmentLimit): Project {
            $locked = Account::query()->whereKey($account->id)->lockForUpdate()->firstOrFail();

            if (! $locked->isActive()) {
                throw AccountSuspended::make($locked->id);
            }

            return $this->projects->create($locked->id, $name, $environmentLimit ?? 2);
        });
    }

    /**
     * Stand up an additional environment under a PROJECT (e.g. staging alongside
     * production), respecting that project's plan allowance.
     *
     * @throws EnvironmentLimitReached
     */
    public function addEnvironment(Project $project, string $name, ?string $domain = null, EnvironmentType $type = EnvironmentType::Production): Environment
    {
        return DB::transaction(function () use ($project, $name, $domain, $type): Environment {
            // Re-check under the row lock so two concurrent adds can't both slip past
            // a limit-of-one.
            $locked = Project::query()->whereKey($project->id)->lockForUpdate()->firstOrFail();
            $account = Account::query()->whereKey($locked->account_id)->firstOrFail();

            if (! $account->isActive()) {
                throw AccountSuspended::make($account->id);
            }

            if (! $locked->isActive()) {
                throw ProjectSuspended::make($locked->id);
            }

            if ($this->projects->remainingEnvironments($locked) < 1) {
                throw EnvironmentLimitReached::make($locked->id, $locked->environment_limit);
            }

            // The project's FIRST environment routes off the bare project name
            // (product.example); every additional stage adds its own name to stay
            // distinct (product-staging.example).
            $isFirst = Environment::query()->where('project_id', $locked->id)->doesntExist();
            $slugSeed = $isFirst ? $locked->name : $locked->name.' '.$name;

            return $this->createEnvironment($locked, $name, $domain, slugSeed: $slugSeed, type: $type);
        });
    }

    /**
     * Create an environment owned by the project (and, denormalized for back-compat
     * reads, its account) and warm its signing key so JWKS/discovery is live the
     * instant it is routable. Left empty of tenants by design. `$slugSeed` is what the
     * routing subdomain derives from.
     */
    private function createEnvironment(Project $project, string $name, ?string $domain, string $slugSeed, EnvironmentType $type): Environment
    {
        $environment = Environment::query()->create([
            'account_id' => $project->account_id,
            'project_id' => $project->id,
            'name' => $name,
            'slug' => $this->uniqueSlug($slugSeed),
            'type' => $type,
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
