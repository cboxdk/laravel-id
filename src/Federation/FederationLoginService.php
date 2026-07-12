<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\UserDirectory;
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
final class FederationLoginService implements FederationFlow
{
    public function __construct(
        private readonly UserDirectory $users,
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
            $user = $this->users->provisionFederated($principal);

            $this->memberships->add($connection->organization_id, $user->id, 'member');

            $session = $this->sessions->start($user->id, $connection->organization_id, ['sso']);

            $this->events->emit(new DomainEvent(
                'user.login',
                ['user_id' => $user->id, 'connection_id' => $connection->id],
                $connection->organization_id,
            ));
            $this->audit->record(new AuditEvent(
                action: 'user.login',
                actorType: ActorType::User,
                actorId: $user->id,
                organizationId: $connection->organization_id,
                targetType: 'connection',
                targetId: $connection->id,
                context: ['method' => 'sso', 'type' => $connection->type->value],
            ));

            return $session;
        });
    }
}
