<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Models\Membership;
use Illuminate\Database\Eloquent\Collection;

/**
 * Membership operations run inside the target org's tenant scope, so the tenant
 * kernel auto-fills `organization_id` and guarantees reads/writes never cross
 * into another org — the service dogfoods the isolation kernel.
 */
final class MembershipService implements Memberships
{
    public function __construct(
        private readonly TenantContext $tenant,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function add(string $organizationId, string $userId, string $role, ?string $invitedBy = null): Membership
    {
        return $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($organizationId, $userId, $role, $invitedBy): Membership {
            $existing = Membership::query()->where('user_id', $userId)->first();

            if ($existing !== null) {
                return $existing;
            }

            $membership = new Membership;
            $membership->fill([
                'user_id' => $userId,
                'role' => $role,
                'status' => MembershipStatus::Active,
                'invited_by' => $invitedBy,
            ]);
            $membership->save();

            $this->emitAndAudit($organizationId, $userId, 'organization.member_added', ['role' => $role]);

            return $membership;
        });
    }

    public function changeRole(string $organizationId, string $userId, string $role): Membership
    {
        return $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($organizationId, $userId, $role): Membership {
            $membership = Membership::query()->where('user_id', $userId)->firstOrFail();
            $membership->update(['role' => $role]);

            $this->emitAndAudit($organizationId, $userId, 'organization.member_role_changed', ['role' => $role]);

            return $membership;
        });
    }

    public function remove(string $organizationId, string $userId): void
    {
        $this->tenant->runAs(GenericTenant::of($organizationId), function () use ($organizationId, $userId): void {
            Membership::query()->where('user_id', $userId)->delete();

            $this->emitAndAudit($organizationId, $userId, 'organization.member_removed', []);
        });
    }

    public function of(string $organizationId, string $userId): ?Membership
    {
        return $this->tenant->runAs(
            GenericTenant::of($organizationId),
            fn (): ?Membership => Membership::query()->where('user_id', $userId)->first(),
        );
    }

    public function forOrganization(string $organizationId): Collection
    {
        return $this->tenant->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => Membership::query()->orderBy('created_at')->get(),
        );
    }

    public function forUser(string $userId): Collection
    {
        // Cross-tenant by nature — a subject's own list of organizations.
        return $this->tenant->withoutScope(
            fn (): Collection => Membership::query()->where('user_id', $userId)->orderBy('created_at')->get(),
        );
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function emitAndAudit(string $organizationId, string $userId, string $action, array $context): void
    {
        $this->events->emit(new DomainEvent($action, ['user_id' => $userId] + $context, $organizationId));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: 'user',
            targetId: $userId,
            context: $context,
        ));
    }
}
