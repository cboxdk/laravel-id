<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\AccountInactive;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Support\Facades\DB;

/**
 * Ties a validated federation principal to the rest of the platform: provisions
 * the user (Identity), ensures org membership (Organization), and starts a
 * session — provider-agnostic, so it serves both SAML and OIDC once an
 * {@see AssertionValidator} has produced a trusted
 * principal.
 */
class FederationLoginService implements FederationFlow
{
    public function __construct(
        private readonly Subjects $subjects,
        private readonly Memberships $memberships,
        private readonly SessionManager $sessions,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function completeLogin(Connection $connection, FederatedPrincipal $principal): Session
    {
        if (! $connection->isActive()) {
            throw ConnectionInactive::make($connection->id);
        }

        return DB::transaction(function () use ($connection, $principal): Session {
            $subject = $this->subjects->provisionFederated($principal);

            // A returning identity whose account was deactivated (e.g. SCIM
            // deprovision, admin disable) must not be handed a fresh session —
            // revoking old sessions alone wouldn't stop a new SSO login.
            if (! $this->subjects->isActive($subject->id)) {
                throw AccountInactive::make($subject->id);
            }

            $this->memberships->add($connection->organization_id, $subject->id, 'member');

            $session = $this->sessions->start($subject->id, $connection->organization_id, ['sso']);

            $this->events->emit(new DomainEvent(
                'user.login',
                ['user_id' => $subject->id, 'connection_id' => $connection->id],
                $connection->organization_id,
            ));
            $this->audit->record(new AuditEvent(
                action: 'user.login',
                actorType: ActorType::User,
                actorId: $subject->id,
                organizationId: $connection->organization_id,
                targetType: 'connection',
                targetId: $connection->id,
                context: ['method' => 'sso', 'type' => $connection->type->value],
            ));

            return $session;
        });
    }
}
