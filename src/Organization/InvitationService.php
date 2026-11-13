<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Identity\Contracts\MailboxProof;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\SecretPrefix;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\InvitationStatus;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Exceptions\InvalidInvitation;
use Cbox\Id\Organization\Models\Invitation;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\ValueObjects\PendingInvitation;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

class InvitationService implements Invitations
{
    private const TTL_DAYS = 7;

    public function __construct(
        private readonly Memberships $memberships,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly ?Subjects $subjects = null,
        private readonly ?MailboxProof $mailboxProof = null,
    ) {}

    public function invite(string $organizationId, string $email, MembershipRole $role, ?string $invitedBy = null, ?string $clientId = null): PendingInvitation
    {
        $token = SecretPrefix::Invitation->mint();

        // Supersede any earlier pending invite for the same address. Read first, so each
        // superseded one can be announced: a receiver mirroring pending invitations would
        // otherwise hold a row for a token that no longer works.
        $superseded = Invitation::query()
            ->where('organization_id', $organizationId)
            ->where('email', $email)
            ->where('app_client_id', $clientId)
            ->where('status', InvitationStatus::Pending->value)
            ->get();

        foreach ($superseded as $previous) {
            $previous->forceFill(['status' => InvitationStatus::Revoked])->save();
            $this->announceRevoked($previous, 'superseded');
        }

        $invitation = new Invitation;
        $invitation->fill([
            'organization_id' => $organizationId,
            'email' => $email,
            'role' => $role,
            'token_hash' => hash('sha256', $token),
            'status' => InvitationStatus::Pending,
            'invited_by' => $invitedBy,
            'app_client_id' => $clientId,
            'expires_at' => now()->addDays(self::TTL_DAYS),
        ]);
        $invitation->save();

        $this->events->emit(new DomainEvent('organization.invitation_created', ['email' => $email, 'role' => $role->value], $organizationId));
        $this->events->emit(new DomainEvent('invitation.created', [
            'invitation_id' => $invitation->id,
            'organization_id' => $organizationId,
            'email' => $email,
            'role' => $role->value,
            'invited_by' => $invitedBy,
            'expires_at' => $invitation->expires_at->toIso8601String(),
        ], $organizationId));
        $this->audit->record(new AuditEvent(
            action: 'organization.invitation_created',
            actorType: ActorType::User,
            actorId: $invitedBy,
            organizationId: $organizationId,
            targetType: 'email',
            targetId: $email,
            context: ['role' => $role->value],
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

            $this->claimInvitedAccount($subjectId, $invitation->email);

            $membership = $this->memberships->add(
                $invitation->organization_id,
                $subjectId,
                $invitation->role,
                invitedBy: $invitation->invited_by,
            );

            $invitation->forceFill([
                'status' => InvitationStatus::Accepted,
                'accepted_at' => now(),
                'accepted_by' => $subjectId,
            ])->save();

            $this->events->emit(new DomainEvent('organization.invitation_accepted', ['user_id' => $subjectId], $invitation->organization_id));
            $this->events->emit(new DomainEvent('invitation.accepted', [
                'directory_revision' => MembershipDirectoryRevision::advance($invitation->organization_id),
                'membership_id' => $membership->id,
                'invitation_id' => $invitation->id,
                'organization_id' => $invitation->organization_id,
                'user_id' => $subjectId,
                'email' => $invitation->email,
                'role' => $invitation->role->value,
            ], $invitation->organization_id));
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

    /**
     * The invitation token was mailed to the invited address, so accepting it proves that
     * mailbox. When the accepting account IS the account under that address and nobody
     * had verified it, it is handed to the token's holder ({@see MailboxProof}) before the
     * membership lands on it: what was set on it before is withdrawn and the address is
     * marked verified. A verified account, an account under another address (a signed-in
     * person accepting with their own account) and an id the subject store does not know
     * are left as they are.
     */
    private function claimInvitedAccount(string $subjectId, string $invitedEmail): void
    {
        $subject = ($this->subjects ?? app(Subjects::class))->find($subjectId);

        if ($subject === null || $subject->emailVerified || $subject->email === null
            || mb_strtolower($subject->email) !== mb_strtolower($invitedEmail)) {
            return;
        }

        ($this->mailboxProof ?? app(MailboxProof::class))->claim($subject, $invitedEmail);
    }

    public function revoke(string $organizationId, string $invitationId, ?string $revokedBy = null): void
    {
        DB::transaction(function () use ($organizationId, $invitationId, $revokedBy): void {
            // The organization is bound in the WHERE clause, so an invitation id from
            // another organization matches nothing rather than being revoked across tenants.
            $invitation = Invitation::query()
                ->whereKey($invitationId)
                ->where('organization_id', $organizationId)
                ->where('status', InvitationStatus::Pending->value)
                ->lockForUpdate()
                ->first();

            // Idempotent: revoking an invitation that is already accepted, revoked or not
            // this organization's changes nothing and announces nothing.
            if ($invitation === null) {
                return;
            }

            $invitation->forceFill(['status' => InvitationStatus::Revoked])->save();

            $this->announceRevoked($invitation, 'revoked');

            $this->audit->record(new AuditEvent(
                action: 'organization.invitation_revoked',
                actorType: $revokedBy !== null ? ActorType::User : ActorType::System,
                actorId: $revokedBy,
                organizationId: $organizationId,
                targetType: 'email',
                targetId: $invitation->email,
                context: ['invitation_id' => $invitation->id],
            ));
        });
    }

    /**
     * `invitation.revoked`, for an explicit revoke and for the earlier invitation a new
     * one to the same address supersedes — the token stops working either way, and
     * `reason` says which.
     */
    private function announceRevoked(Invitation $invitation, string $reason): void
    {
        $this->events->emit(new DomainEvent('invitation.revoked', [
            'invitation_id' => $invitation->id,
            'organization_id' => $invitation->organization_id,
            'email' => $invitation->email,
            'reason' => $reason,
        ], $invitation->organization_id));
    }

    public function byToken(string $token): ?Invitation
    {
        return Invitation::query()->where('token_hash', hash('sha256', $token))->first();
    }

    public function pending(string $organizationId, ?int $limit = null): Collection
    {
        $query = $this->pendingQuery($organizationId)->orderByDesc('created_at');

        if ($limit !== null) {
            $query->limit($limit);
        }

        return $query->get();
    }

    public function countPending(string $organizationId): int
    {
        return $this->pendingQuery($organizationId)->count();
    }

    /** @return Builder<Invitation> */
    private function pendingQuery(string $organizationId): Builder
    {
        return Invitation::query()
            ->where('organization_id', $organizationId)
            ->where('status', InvitationStatus::Pending->value)
            ->where('expires_at', '>', now());
    }
}
