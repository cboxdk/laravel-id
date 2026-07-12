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

final class OrganizationService implements Organizations
{
    public function __construct(
        private readonly OrganizationHierarchy $hierarchy,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
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

    public function find(string $id): ?Organization
    {
        return Organization::query()->whereKey($id)->first();
    }

    public function bySlug(string $slug): ?Organization
    {
        return Organization::query()->where('slug', $slug)->first();
    }
}
