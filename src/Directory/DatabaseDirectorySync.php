<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DeprovisioningPolicy;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Enums\DeprovisioningMode;
use Cbox\Id\Directory\Exceptions\DirectoryUserNameTaken;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Illuminate\Support\Facades\DB;

/**
 * SCIM provisioning that ties the directory to the rest of the platform: it
 * provisions a local user (Identity), links the SCIM resource, manages org
 * membership (Organization), and — critically — revokes sessions the instant a
 * user is deactivated or deprovisioned.
 *
 * HOW FAR a deprovision reaches is the environment's {@see DeprovisioningMode}: the whole
 * account (the default — the directory owns who has an account), or only this
 * organization's membership (a shared environment, where the account is the person's own
 * and one employer must not be able to lock them out of everything else).
 */
class DatabaseDirectorySync implements DirectorySync
{
    public function __construct(
        private readonly Subjects $subjects,
        private readonly Memberships $memberships,
        private readonly SessionManager $sessions,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly DeprovisioningPolicy $deprovisioning,
    ) {}

    public function provisionUser(string $directoryId, ScimUser $user): DirectoryUser
    {
        $directory = Directory::query()->whereKey($directoryId)->firstOrFail();

        return DB::transaction(function () use ($directory, $user): DirectoryUser {
            // userName is unique per directory (ServiceProviderConfig advertises
            // uniqueness=server). A collision with a DIFFERENT externalId is a 409, not
            // a duplicate userName the IdP can never reconcile. Same-externalId re-pushes
            // fall through to updateOrCreate below (an update, not a conflict).
            //
            // Matched on the folded column, because RFC 7643 defines userName as
            // caseExact:false. Comparing the raw JSON value made this check inherit the
            // database's collation: on PostgreSQL `Dana.Rivera` and `dana.rivera` were
            // two different people, so the IdP's pre-provision lookup missed, this guard
            // missed, and a second directory row and a second subject were created.
            $nameTaken = DirectoryUser::query()
                ->where('directory_id', $directory->id)
                ->where('user_name_lower', DirectoryUser::normalize($user->userName))
                ->where('external_id', '!=', $user->externalId)
                ->exists();

            if ($nameTaken) {
                throw DirectoryUserNameTaken::make($user->userName);
            }

            $subject = $this->subjects->provisionFederated(new FederatedPrincipal(
                provider: 'scim',
                subject: $directory->id.'|'.$user->externalId,
                email: $user->email,
                name: $user->displayName ?? $user->userName,
                connectionId: $directory->id,
                raw: $user->raw,
            ));

            $directoryUser = DirectoryUser::query()->updateOrCreate(
                ['directory_id' => $directory->id, 'external_id' => $user->externalId],
                ['resource' => $user->raw, 'user_id' => $subject->id, 'active' => $user->active],
            );

            $mode = $this->deprovisioning->modeFor($directory);

            if ($user->active) {
                // Only a directory that owns the account may bring it back. In membership
                // mode an account somebody else disabled — an operator, the person's own
                // erasure request — stays disabled; the directory only restores what it
                // is allowed to take away, which is the membership.
                if ($mode->ownsAccount()) {
                    $this->subjects->reactivate($subject->id);
                }

                $this->memberships->add($directory->organization_id, $subject->id, MembershipRole::Member);

                $this->emitAndAudit($directory, $user->externalId, 'directory.user.provisioned', ['user_id' => $subject->id]);

                return $directoryUser;
            }

            $this->withdraw($directory, $subject->id, $mode);

            $this->emitAndAudit($directory, $user->externalId, 'directory.user.deactivated', [
                'user_id' => $subject->id,
            ] + $this->reach($mode, 'directory_deactivated'));

            return $directoryUser;
        });
    }

    public function deprovisionUser(string $directoryId, string $externalId): void
    {
        $directory = Directory::query()->whereKey($directoryId)->firstOrFail();

        $directoryUser = DirectoryUser::query()
            ->where('directory_id', $directoryId)
            ->where('external_id', $externalId)
            ->first();

        if ($directoryUser === null) {
            return;
        }

        DB::transaction(function () use ($directory, $directoryUser, $externalId): void {
            $directoryUser->update(['active' => false]);

            $mode = $this->deprovisioning->modeFor($directory);

            if ($directoryUser->user_id !== null) {
                $this->withdraw($directory, $directoryUser->user_id, $mode);
            }

            $this->emitAndAudit($directory, $externalId, 'directory.user.deprovisioned', [
                'user_id' => $directoryUser->user_id,
            ] + $this->reach($mode, 'directory_removed'));
        });
    }

    /**
     * Take away what this directory gave the person, as far as the mode allows.
     */
    private function withdraw(Directory $directory, string $userId, DeprovisioningMode $mode): void
    {
        if ($mode->ownsAccount()) {
            // Deactivate the account itself, not just its sessions — otherwise
            // the deprovisioned user could simply log back in via SSO/password.
            $this->subjects->deactivate($userId);
            $this->memberships->remove($directory->organization_id, $userId);
            $this->sessions->revokeAllForUser($userId);

            return;
        }

        // MEMBERSHIP ONLY. Removing the membership drops the role assignments with it and
        // emits `organization.member_removed`, which is what withdraws this organization's
        // refresh tokens and tells the applications signed in to it (Back-Channel Logout).
        // The account, and everything the person holds in other organizations, is untouched.
        $this->memberships->remove($directory->organization_id, $userId);

        // The sign-in sessions bound to THIS organization end too: one started through the
        // organization's SSO would otherwise go on vouching for a person the organization
        // has just let go. One at a time through the session manager, so each is audited
        // and propagated like any other revocation. Sessions bound to another organization,
        // or to none, are the person's own and stay.
        Session::query()
            ->where('user_id', $userId)
            ->where('organization_id', $directory->organization_id)
            ->whereNull('revoked_at')
            ->get(['id'])
            ->each(fn (Session $session) => $this->sessions->revoke($session->id));
    }

    /**
     * What the event and the audit entry say about how far the deprovision reached, so a
     * reader does not have to know the environment's mode to tell whether the account
     * survived.
     *
     * @return array{reason: string, deprovisioning: string, account_deactivated: bool}
     */
    private function reach(DeprovisioningMode $mode, string $reason): array
    {
        return [
            'reason' => $reason,
            'deprovisioning' => $mode->value,
            'account_deactivated' => $mode->ownsAccount(),
        ];
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function emitAndAudit(Directory $directory, string $externalId, string $action, array $context): void
    {
        $this->events->emit(new DomainEvent($action, ['external_id' => $externalId] + $context, $directory->organization_id));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::Service,
            actorId: $directory->id,
            organizationId: $directory->organization_id,
            targetType: 'directory_user',
            targetId: $externalId,
            context: $context,
        ));
    }
}
