<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\OrganizationStatus;
use Cbox\Id\Organization\Exceptions\SlugAlreadyTaken;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Support\Facades\DB;

class OrganizationService implements Organizations
{
    public function __construct(
        private readonly OrganizationHierarchy $hierarchy,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly EnvironmentResolutionCache $resolutionCache,
    ) {}

    public function create(NewOrganization $input): Organization
    {
        return DB::transaction(function () use ($input): Organization {
            if (Organization::query()->where('slug', $input->slug)->exists()) {
                throw SlugAlreadyTaken::make($input->slug);
            }

            $organization = new Organization;
            $organization->fill([
                'name' => $input->name,
                'slug' => $input->slug,
                'type' => $input->type,
                'status' => OrganizationStatus::Active,
                'parent_id' => $input->parentId,
                'settings' => $input->settings,
            ]);
            $organization->save();

            $this->hierarchy->attach($organization->id, $input->parentId);

            $this->events->emit(new DomainEvent(
                'organization.created',
                ['id' => $organization->id, 'slug' => $organization->slug],
                $organization->id,
            ));

            $this->audit->record(new AuditEvent(
                action: 'organization.created',
                actorType: ActorType::System,
                organizationId: $organization->id,
                targetType: 'organization',
                targetId: $organization->id,
                context: ['slug' => $organization->slug, 'type' => $organization->type->value],
            ));

            return $organization;
        });
    }

    public function updateSettings(string $id, array $settings): Organization
    {
        $organization = Organization::query()->whereKey($id)->firstOrFail();
        $organization->settings = array_merge($organization->settings, $settings);
        $organization->save();

        $this->audit->record(new AuditEvent(
            action: 'organization.settings_updated',
            actorType: ActorType::System,
            organizationId: $organization->id,
            targetType: 'organization',
            targetId: $organization->id,
            context: ['keys' => array_keys($settings)],
        ));

        return $organization;
    }

    public function suspend(string $id, string $actorId): Organization
    {
        return $this->transitionStatus($id, OrganizationStatus::Suspended, 'organization.suspended', $actorId);
    }

    public function reactivate(string $id, string $actorId): Organization
    {
        return $this->transitionStatus($id, OrganizationStatus::Active, 'organization.reactivated', $actorId);
    }

    public function archive(string $id, string $actorId): Organization
    {
        $organization = Organization::query()->whereKey($id)->firstOrFail();

        // Idempotent, and deliberately BEFORE the write: replaying an archive must
        // not append a second audit entry, or the trail stops answering "when was
        // this organization archived, and by whom".
        if ($organization->status === OrganizationStatus::Deleted) {
            return $organization;
        }

        return $this->transitionStatus($id, OrganizationStatus::Deleted, 'organization.archived', $actorId);
    }

    public function find(string $id): ?Organization
    {
        return Organization::query()->whereKey($id)->first();
    }

    public function findMany(array $ids): array
    {
        if ($ids === []) {
            return [];
        }

        return Organization::query()
            ->whereKey(array_values(array_unique($ids)))
            ->get()
            ->keyBy(function (Organization $o): string {
                $key = $o->getKey();

                return is_scalar($key) ? (string) $key : '';
            })
            ->all();
    }

    public function bySlug(string $slug): ?Organization
    {
        return Organization::query()->where('slug', $slug)->first();
    }

    /**
     * Write the status, invalidate the tenant's resolution cache, then announce it — in
     * that order, as one operation the caller cannot half-perform.
     *
     * Nothing is recorded when the status did not actually change. Every verb here is
     * documented idempotent, and a re-suspension that appended a second
     * `organization.suspended` would leave the trail unable to answer when the
     * organization was suspended and by whom — and would deliver a duplicate webhook for
     * a transition that never happened. `DatabaseAccounts::transitionStatus()` carried
     * this rule for the account plane; when ownership moved onto the organization only
     * the archive case came with it.
     */
    private function transitionStatus(string $id, OrganizationStatus $status, string $action, string $actorId): Organization
    {
        $organization = Organization::query()->whereKey($id)->firstOrFail();

        if ($organization->status === $status) {
            return $organization;
        }

        $organization->status = $status;
        $organization->save();

        $this->forgetResolvedEnvironments($organization->id);

        $this->events->emit(new DomainEvent(
            $action,
            ['id' => $organization->id, 'status' => $status->value],
            $organization->id,
        ));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::Operator,
            actorId: $actorId,
            organizationId: $organization->id,
            targetType: 'organization',
            targetId: $organization->id,
            context: ['status' => $status->value],
        ));

        return $organization;
    }

    /**
     * Suspending an organization is the platform's off-switch for a whole customer: every
     * environment it owns must stop serving auth on the NEXT request, not whenever a cache
     * TTL happens to lapse.
     *
     * The environments are untouched by the status write — {@see DatabaseEnvironmentResolver}
     * gates liveness by reading `organizations` separately — so no environment model event
     * fires and {@see Models\Environment::booted()} never runs. The invalidation has to be
     * explicit here, and this is the only place it can be. Without it the suspension wrote
     * the row and changed nothing anybody could observe: the host kept resolving, kept
     * serving, and the console kept saying "suspended".
     *
     * Dropping each environment's resolved entry is enough. The host mappings survive, miss
     * on the `env:` entry, and fall through to a full live resolution — which now refuses.
     * So no host has to be enumerated, and reactivation restores service just as promptly.
     *
     * OWNERSHIP RUNS THROUGH THE PROJECT — environment → project → organization. It was one
     * read against `environments.account_id`; that column was a denormalized copy of the
     * same fact, and a copy of ownership is a second place for ownership to be wrong.
     *
     * The hierarchy is deliberately NOT walked: this matches the liveness gate exactly, and
     * the gate compares an environment's own owning organization to 'active'. Invalidating a
     * parent's descendants would drop entries whose resolution the write cannot change.
     *
     * Raw query, unscoped on purpose. `projects` is environment-owned, so `Project::query()`
     * would be scoped to whichever environment is current — and the caller here is the
     * platform root, suspending a customer that lives in a different one.
     */
    private function forgetResolvedEnvironments(string $organizationId): void
    {
        $environments = DB::table('environments')
            ->join('projects', 'projects.id', '=', 'environments.project_id')
            ->where('projects.organization_id', $organizationId)
            ->get(['environments.id', 'environments.domain', 'environments.slug']);

        foreach ($environments as $environment) {
            if (is_string($environment->id) && $environment->id !== '') {
                $this->resolutionCache->forgetEnvironment($environment->id);
            }

            // AND THE HOSTS, because a refusal is now remembered for ten seconds and the
            // whole point of this method is that reactivating restores service on the
            // next request rather than when an entry lapses. Both kinds of host a row
            // answers on are enumerable from it — the custom domain, and the slug under
            // each configured base domain — which is the same enumeration the model's
            // own save hook does.
            $this->resolutionCache->forgetHost(is_string($environment->domain) ? $environment->domain : null);

            if (is_string($environment->slug) && $environment->slug !== '') {
                foreach ($this->resolutionCache->baseDomains() as $base) {
                    $this->resolutionCache->forgetHost($environment->slug.'.'.$base);
                }
            }
        }
    }
}
