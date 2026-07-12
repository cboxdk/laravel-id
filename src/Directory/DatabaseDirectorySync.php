<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Support\Facades\DB;

/**
 * SCIM provisioning that ties the directory to the rest of the platform: it
 * provisions a local user (Identity), links the SCIM resource, manages org
 * membership (Organization), and — critically — revokes sessions the instant a
 * user is deactivated or deprovisioned.
 */
final class DatabaseDirectorySync implements DirectorySync
{
    public function __construct(
        private readonly Subjects $subjects,
        private readonly Memberships $memberships,
        private readonly SessionManager $sessions,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function provisionUser(string $directoryId, ScimUser $user): DirectoryUser
    {
        $directory = Directory::query()->whereKey($directoryId)->firstOrFail();

        return DB::transaction(function () use ($directory, $user): DirectoryUser {
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

            if ($user->active) {
                $this->memberships->add($directory->organization_id, $subject->id, 'member');
                $action = 'directory.user.provisioned';
            } else {
                $this->memberships->remove($directory->organization_id, $subject->id);
                $this->sessions->revokeAllForUser($subject->id);
                $action = 'directory.user.deactivated';
            }

            $this->emitAndAudit($directory, $user->externalId, $action, ['user_id' => $subject->id]);

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

            if ($directoryUser->user_id !== null) {
                $this->memberships->remove($directory->organization_id, $directoryUser->user_id);
                $this->sessions->revokeAllForUser($directoryUser->user_id);
            }

            $this->emitAndAudit($directory, $externalId, 'directory.user.deprovisioned', [
                'user_id' => $directoryUser->user_id,
            ]);
        });
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
