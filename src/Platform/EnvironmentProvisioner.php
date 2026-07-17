<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Platform\ValueObjects\EnvironmentBlueprint;
use Cbox\Id\Platform\ValueObjects\ProvisionedEnvironment;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Self-serve provisioning of a whole new environment — a customer's own IdP. This is
 * a PLATFORM-level operation (environments have no parent environment), so it runs
 * above any tenant scope: it creates the environment, then bootstraps its first owner
 * and organization INSIDE the new environment's scope. That the capability lives here
 * — never inside a tenant environment — is what stops a customer's IdP from spawning
 * further IdPs (the tenancy is a tree rooted at the platform, not a recursion).
 *
 * The whole thing is one transaction: a failed bootstrap never leaves a half-born
 * environment routable.
 */
final class EnvironmentProvisioner
{
    public function __construct(
        private readonly EnvironmentContext $context,
        private readonly KeyManager $keys,
        private readonly Subjects $subjects,
        private readonly Organizations $organizations,
        private readonly Memberships $memberships,
    ) {}

    public function provision(EnvironmentBlueprint $blueprint): ProvisionedEnvironment
    {
        return DB::transaction(function () use ($blueprint): ProvisionedEnvironment {
            $environment = Environment::query()->create([
                'name' => $blueprint->name,
                'slug' => $this->uniqueSlug($blueprint->name),
                'domain' => $blueprint->domain,
                'status' => 'active',
            ]);

            return $this->context->runAs($environment, function () use ($environment, $blueprint): ProvisionedEnvironment {
                // Warm the new plane's signing key so its JWKS/discovery is live at once.
                $this->keys->activeSigningKey();

                $owner = $this->subjects->create($blueprint->ownerEmail, $blueprint->ownerName, $blueprint->ownerPassword);

                $organization = $this->organizations->create(new NewOrganization(
                    $blueprint->organizationName,
                    $this->slug($blueprint->organizationName),
                ));

                // The signer-up owns their new realm — the first admin of their IdP.
                $this->memberships->add($organization->id, $owner->id, 'owner');

                return new ProvisionedEnvironment($environment, $owner, $organization);
            });
        });
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

        return $slug !== '' ? $slug : 'org-'.Str::lower(Str::random(6));
    }
}
