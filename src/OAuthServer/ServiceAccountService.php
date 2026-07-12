<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\ServiceAccounts;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\ServiceAccount;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Support\Facades\DB;

final class ServiceAccountService implements ServiceAccounts
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function create(string $organizationId, string $name, array $scopes = []): RegisteredClient
    {
        return DB::transaction(function () use ($organizationId, $name, $scopes): RegisteredClient {
            $registered = $this->clients->register(new NewClient(
                name: $name,
                type: ClientType::Confidential,
                grantTypes: ['client_credentials'],
                scopes: $scopes,
                organizationId: $organizationId,
            ));

            ServiceAccount::query()->create([
                'organization_id' => $organizationId,
                'name' => $name,
                'client_id' => $registered->client->client_id,
                'status' => 'active',
            ]);

            $this->events->emit(new DomainEvent(
                'service_account.created',
                ['client_id' => $registered->client->client_id],
                $organizationId,
            ));
            $this->audit->record(new AuditEvent(
                action: 'service_account.created',
                actorType: ActorType::System,
                organizationId: $organizationId,
                targetType: 'service_account',
                targetId: $registered->client->client_id,
            ));

            return $registered;
        });
    }
}
