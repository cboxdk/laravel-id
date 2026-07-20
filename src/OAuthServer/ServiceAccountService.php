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
use Cbox\Id\OAuthServer\Exceptions\UnknownServiceAccount;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\ServiceAccount;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Illuminate\Support\Facades\DB;

class ServiceAccountService implements ServiceAccounts
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

    public function rotate(string $clientId): RegisteredClient
    {
        return DB::transaction(function () use ($clientId): RegisteredClient {
            $account = ServiceAccount::query()->where('client_id', $clientId)->first();
            $client = $this->clients->byClientId($clientId);

            if ($account === null || $client === null) {
                throw UnknownServiceAccount::make($clientId);
            }

            // The successor inherits the same identity and privileges. Both are
            // valid until the predecessor is retired, so cutover has no downtime.
            $registered = $this->clients->register(new NewClient(
                name: $account->name,
                type: ClientType::Confidential,
                grantTypes: ['client_credentials'],
                scopes: array_values($client->scopes),
                organizationId: $account->organization_id,
            ));

            ServiceAccount::query()->create([
                'organization_id' => $account->organization_id,
                'name' => $account->name,
                'client_id' => $registered->client->client_id,
                'rotated_from' => $clientId,
                'status' => 'active',
            ]);

            $this->events->emit(new DomainEvent(
                'service_account.rotated',
                ['from_client_id' => $clientId, 'to_client_id' => $registered->client->client_id],
                $account->organization_id,
            ));
            $this->audit->record(new AuditEvent(
                action: 'service_account.rotated',
                actorType: ActorType::System,
                organizationId: $account->organization_id,
                targetType: 'service_account',
                targetId: $registered->client->client_id,
                context: ['rotated_from' => $clientId],
            ));

            return $registered;
        });
    }

    public function retire(string $clientId): void
    {
        DB::transaction(function () use ($clientId): void {
            $account = ServiceAccount::query()->where('client_id', $clientId)->first();

            if ($account === null) {
                throw UnknownServiceAccount::make($clientId);
            }

            if ($account->status === 'retired') {
                return; // idempotent
            }

            $account->forceFill(['status' => 'retired', 'retired_at' => now()])->save();

            // Remove the client so it can mint no further tokens, and revoke every
            // access token it already issued.
            Client::query()->where('client_id', $clientId)->delete();
            AccessToken::query()
                ->where('client_id', $clientId)
                ->whereNull('revoked_at')
                ->update(['revoked_at' => now()]);

            $this->events->emit(new DomainEvent(
                'service_account.retired',
                ['client_id' => $clientId],
                $account->organization_id,
            ));
            $this->audit->record(new AuditEvent(
                action: 'service_account.retired',
                actorType: ActorType::System,
                organizationId: $account->organization_id,
                targetType: 'service_account',
                targetId: $clientId,
            ));
        });
    }
}
