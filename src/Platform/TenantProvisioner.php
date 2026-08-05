<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\EnvironmentStatus;
use Cbox\Id\Organization\Enums\EnvironmentType;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Platform\Contracts\Projects;
use Cbox\Id\Platform\Exceptions\EnvironmentLimitReached;
use Cbox\Id\Platform\Exceptions\OrganizationSuspended;
use Cbox\Id\Platform\Exceptions\ProjectSuspended;
use Cbox\Id\Platform\Models\Project;
use Cbox\Id\Platform\ValueObjects\ProvisionedTenant;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;

/**
 * Self-serve provisioning of a whole customer — the organization they are, the owner who
 * signs in for them, their first IdP product, and that product's first environment.
 *
 * A PLATFORM-level operation. The organization it creates lives in the platform root, and
 * the environment it creates is a tenant of its own, so this runs above any one tenant's
 * scope and switches into the root explicitly rather than inheriting it.
 *
 * The layering is Organization → Project → Environment → Subject, one way and never the
 * reverse: the management plane never seeds the end-user plane, so a provisioned
 * environment is born EMPTY. Billing lives on the PROJECT, so one customer can own several
 * independently-billed products.
 *
 * IT WAS `AccountProvisioner`, and it created an `Account` row and then an organization
 * beside it that shadowed it one-to-one. Two rows for one customer, two role vocabularies,
 * two answers to "who may act for them" — and a per-member environment grant that lived on
 * one and was read from the other. The account row is gone rather than reconciled.
 *
 * Everything is one transaction: a failed step never leaves a half-born customer or a
 * routable-but-orphaned environment.
 */
class TenantProvisioner
{
    public function __construct(
        private readonly EnvironmentContext $context,
        private readonly KeyManager $keys,
        private readonly Subjects $subjects,
        private readonly Memberships $memberships,
        private readonly Projects $projects,
        private readonly Organizations $organizations,
        private readonly PlatformRoot $platformRoot,
    ) {}

    public function provision(TenantBlueprint $blueprint): ProvisionedTenant
    {
        return DB::transaction(function () use ($blueprint): ProvisionedTenant {
            $platformRoot = $this->platformRoot->model();

            if ($platformRoot === null) {
                // Refused rather than worked around. There used to be a bootstrap window
                // here — an account provisioned before the deployment had a root, whose
                // members had no subject and whose organization did not exist — and every
                // caller downstream grew a null check for a state only the installer could
                // produce. The installer stamps the root first; if it has not, this is a
                // broken install and saying so is more useful than half a customer.
                throw new InvalidArgumentException(
                    'No platform-root environment exists. Run the installer before provisioning a tenant.',
                );
            }

            // THE CUSTOMER, and the only row that stands for them. Created in the platform
            // root, which is the environment the platform's own people and its customers'
            // organizations live in — a tenant's END USERS live in that tenant's own
            // environments instead, which is the whole distinction the root draws.
            [$organization, $owner, $membership] = $this->context->runAs(
                $platformRoot,
                function () use ($blueprint): array {
                    $organization = $this->organizations->create(new NewOrganization(
                        name: $blueprint->organizationName,
                        slug: $this->uniqueOrganizationSlug($blueprint->organizationName),
                    ));

                    // One credential of record. The owner is an ordinary subject — the
                    // same row shape a tenant's own user occupies — rather than a member
                    // row with its own password column, which is what the account plane
                    // had and what made "who is signed in" a question with two answers.
                    $owner = $this->subjects->create(
                        $blueprint->ownerEmail,
                        $blueprint->ownerName,
                        $blueprint->ownerPassword,
                    );

                    // …and the authority is the MEMBERSHIP, held separately, because it is
                    // true here and nowhere else. The same person may own this
                    // organization and be a viewer in another.
                    $membership = $this->memberships->add($organization->id, $owner->id, MembershipRole::Owner);

                    return [$organization, $owner, $membership];
                },
            );

            // The customer's first IdP product. Named after them by default; its plan
            // allowance is the blueprint's limit, because billing lives on the product.
            $project = $this->projects->createForOrganization(
                $organization->id,
                $blueprint->organizationName,
                $blueprint->environmentLimit,
            );

            // The routing slug (subdomain) derives from the PRODUCT's identity, not the
            // stage name — so "Acme" gets acme.example rather than a generic
            // "production.example" every customer would collide on.
            $environment = $this->createEnvironment(
                $project,
                $blueprint->environmentName,
                $blueprint->domain,
                slugSeed: $project->name,
                type: EnvironmentType::Production,
            );

            return new ProvisionedTenant($organization, $owner, $membership, $project, $environment);
        });
    }

    /**
     * Stand up an additional IdP product under an existing organization — a
     * separately-billed product alongside the first, with no second login.
     */
    public function addProject(Organization $organization, string $name, ?int $environmentLimit = null): Project
    {
        return DB::transaction(function () use ($organization, $name, $environmentLimit): Project {
            $locked = $this->lockedActiveOrganization($organization->id);

            return $this->projects->createForOrganization(
                $locked->id,
                $name,
                $environmentLimit ?? 2,
            );
        });
    }

    public function addEnvironment(Project $project, string $name, ?string $domain = null, EnvironmentType $type = EnvironmentType::Production): Environment
    {
        return DB::transaction(function () use ($project, $name, $domain, $type): Environment {
            // Re-check under the row lock so two concurrent adds can't both slip past
            // a limit-of-one.
            $locked = Project::query()->whereKey($project->id)->lockForUpdate()->firstOrFail();

            // THE OWNER FIRST, then the product. Both were checked when the owner was an
            // account; only the project check survived the move, so a suspended customer
            // could still add environments to a product that was itself still active.
            $this->lockedActiveOrganization($locked->organization_id);

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
     * Create an environment owned by the project and warm its signing key so
     * JWKS/discovery is live the instant it is routable. Left empty of tenants by design. `$slugSeed` is what the
     * routing subdomain derives from.
     */
    private function createEnvironment(Project $project, string $name, ?string $domain, string $slugSeed, EnvironmentType $type): Environment
    {
        // An operator-supplied domain here is trusted (this is the operator provisioning
        // path, not tenant self-serve), so stamp it verified — that keeps the invariant
        // "domain set ⇒ verified" whole, so the env both ROUTES and ISSUES on the same
        // host (no discovery iss/host mismatch). Tenant self-serve still goes through
        // EnvironmentDomainService's DNS proof. A domain already owned by another env is
        // refused rather than silently colliding.
        $domain = $domain !== null && $domain !== '' ? strtolower(trim($domain)) : null;

        if ($domain !== null) {
            $owner = Environment::query()->where('domain', $domain)->value('id');

            if ($owner !== null) {
                throw new InvalidArgumentException("The domain [{$domain}] is already in use by another environment.");
            }
        }

        $environment = Environment::query()->create([
            'project_id' => $project->id,
            'name' => $name,
            'slug' => $this->uniqueSlug($slugSeed),
            'type' => $type,
            'domain' => $domain,
            'domain_verified_at' => $domain !== null ? now() : null,
            'status' => EnvironmentStatus::Active,
        ]);

        $this->context->runAs($environment, function (): void {
            $this->keys->activeSigningKey();
        });

        return $environment;
    }

    /**
     * The organization, locked, and only if it may still be provisioned for.
     *
     * Read inside the platform root because `organizations` is environment-owned: asked from
     * a tenant host the deny-by-default scope answers "no such organization", which on a
     * write path would read as "suspended" for a perfectly active customer.
     *
     * `revokesAccess()` rather than a comparison against `Active`. `Deleted` is written by
     * `archive()` and reads like a soft-delete marker, so a `!== Suspended` test here would
     * happily sell a new product to an archived customer.
     *
     * An organization that cannot be produced is refused, not permitted — the same direction
     * a suspension takes, which is the only safe reading of a missing owner on a write path.
     */
    private function lockedActiveOrganization(string $organizationId): Organization
    {
        $organization = $this->platformRoot->run(
            fn (): ?Organization => Organization::query()->whereKey($organizationId)->lockForUpdate()->first(),
        );

        if (! $organization instanceof Organization || $organization->status->revokesAccess()) {
            throw OrganizationSuspended::make($organizationId);
        }

        return $organization;
    }

    /**
     * A slug unique across ORGANIZATIONS, resolved inside the platform root.
     *
     * The uniqueness index is `(environment_id, slug)`, so this is only correct while the
     * root is the current scope — which `provision()` guarantees by calling it from inside
     * `runAs()`. Called from outside it, the deny-by-default tenancy scope answers "no
     * collisions" for every candidate and hands back the first one.
     */
    private function uniqueOrganizationSlug(string $name): string
    {
        $base = $this->slug($name);
        $slug = $base;
        $suffix = 1;

        while (Organization::query()->where('slug', $slug)->exists()) {
            $slug = $base.'-'.(++$suffix);
        }

        return $slug;
    }

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
