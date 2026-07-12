<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\InvitationStatus;
use Cbox\Id\Organization\Exceptions\InvalidInvitation;
use Cbox\Id\Organization\Models\Invitation;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\ValueObjects\PendingInvitation;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

final class InvitationService implements Invitations
{
    private const TTL_DAYS = 7;

    public function __construct(
        private readonly Memberships $memberships,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function invite(string $organizationId, string $email, string $role, ?string $invitedBy = null): PendingInvitation
    {
        $token = 'inv_'.bin2hex(random_bytes(32));

        // Supersede any earlier pending invite for the same address.
        Invitation::query()
            ->where('organization_id', $organizationId)
            ->where('email', $email)
            ->where('status', InvitationStatus::Pending->value)
            ->update(['status' => InvitationStatus::Revoked->value]);

        $invitation = new Invitation;
        $invitation->fill([
            'organization_id' => $organizationId,
            'email' => $email,
            'role' => $role,
            'token_hash' => hash('sha256', $token),
            'status' => InvitationStatus::Pending,
            'invited_by' => $invitedBy,
            'expires_at' => now()->addDays(self::TTL_DAYS),
        ]);
        $invitation->save();

        $this->events->emit(new DomainEvent('organization.invitation_created', ['email' => $email, 'role' => $role], $organizationId));
        $this->audit->record(new AuditEvent(
            action: 'organization.invitation_created',
            actorType: ActorType::User,
            actorId: $invitedBy,
            organizationId: $organizationId,
            targetType: 'email',
            targetId: $email,
            context: ['role' => $role],
        ));

        return new PendingInvitation($invitation, $token);
    }

    public function accept(string $token, string $subjectId): Membership
    {
        return DB::transaction(function () use ($token, $subjectId): Membership {
            $invitation = Invitation::query()
                ->where('token_hash', hash('sha256', $token))
                ->lockForUpdate()
                ->first();

            if ($invitation === null || ! $invitation->isPending()) {
                throw InvalidInvitation::make();
            }

            $membership = $this->memberships->add(
                $invitation->organization_id,
                $subjectId,
                $invitation->role,
                invitedBy: $invitation->invited_by,
            );

            $invitation->forceFill([
                'status' => InvitationStatus::Accepted,
                'accepted_at' => now(),
            ])->save();

            $this->events->emit(new DomainEvent('organization.invitation_accepted', ['user_id' => $subjectId], $invitation->organization_id));
            $this->audit->record(new AuditEvent(
                action: 'organization.invitation_accepted',
                actorType: ActorType::User,
                actorId: $subjectId,
                organizationId: $invitation->organization_id,
                targetType: 'user',
                targetId: $subjectId,
            ));

            return $membership;
        });
    }

    public function revoke(string $organizationId, string $invitationId): void
    {
        Invitation::query()
            ->whereKey($invitationId)
            ->where('organization_id', $organizationId)
            ->where('status', InvitationStatus::Pending->value)
            ->update(['status' => InvitationStatus::Revoked->value]);
    }

    public function byToken(string $token): ?Invitation
    {
        return Invitation::query()->where('token_hash', hash('sha256', $token))->first();
    }

    public function pending(string $organizationId): Collection
    {
        return Invitation::query()
            ->where('organization_id', $organizationId)
            ->where('status', InvitationStatus::Pending->value)
            ->where('expires_at', '>', now())
            ->orderByDesc('created_at')
            ->get();
    }
}
