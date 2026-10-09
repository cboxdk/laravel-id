<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\Enums\PipeConnectionStatus;
use Cbox\Id\Pipes\Exceptions\PipeConnectFailed;
use Cbox\Id\Pipes\Exceptions\PipeConnectionNotFound;
use Cbox\Id\Pipes\Exceptions\PipeNotFound;
use Cbox\Id\Pipes\Exceptions\PipeProviderUnavailable;
use Cbox\Id\Pipes\Exceptions\PipeTokenRejected;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\Support\PipeSecrets;
use Cbox\Id\Pipes\ValueObjects\PipeAuthorization;
use Cbox\Id\Pipes\ValueObjects\PipeConnectState;
use Cbox\Id\Pipes\ValueObjects\PipeTokenSet;
use Throwable;

/**
 * Database-backed {@see PipeConnections}: the connect flow, and a person's list of
 * connected accounts.
 *
 * The security of the flow rests on three things the host cannot get wrong by accident,
 * because they are checked here rather than left to it:
 *
 *  - the callback's `state` must match the one stashed in the browser that started the
 *    flow (constant-time), so a callback cannot be replayed into another session;
 *  - the code is exchanged with the PKCE verifier only that browser's session holds;
 *  - the connection is written for the pipe and the person recorded at START, never for
 *    whatever the callback request claims.
 */
class DatabasePipeConnections implements PipeConnections
{
    use ResolvesEnvironment;

    public function __construct(
        private readonly PipeOAuthClient $client,
        private readonly PipeSecrets $secrets,
        private readonly AuditLog $audit,
        private readonly EventBus $events,
    ) {}

    public function start(string $provider, string $userId, string $redirectUri): PipeAuthorization
    {
        $this->environments()->requireEnvironment();

        $pipe = Pipe::query()->where('provider', $provider)->where('enabled', true)->first()
            ?? throw PipeNotFound::forProvider($provider);
        $entry = $pipe->catalogueEntry() ?? throw PipeNotFound::forProvider($provider);

        $verifier = PipeOAuthClient::codeVerifier();
        $flow = new PipeConnectState(
            state: bin2hex(random_bytes(16)),
            codeVerifier: $verifier,
            pipeId: $pipe->id,
            userId: $userId,
            redirectUri: $redirectUri,
        );

        $url = $this->client->authorizeUrl(
            $entry,
            $pipe,
            $pipe->scopes,
            $redirectUri,
            $flow->state,
            PipeOAuthClient::codeChallenge($verifier),
        );

        return new PipeAuthorization($url, $flow);
    }

    public function complete(PipeConnectState $flow, string $state, string $code): PipeConnection
    {
        $this->environments()->requireEnvironment();

        if (! $flow->matches($state) || $code === '') {
            throw PipeConnectFailed::because('state_mismatch');
        }

        $pipe = Pipe::query()->whereKey($flow->pipeId)->where('enabled', true)->first();
        $entry = $pipe?->catalogueEntry();

        if ($pipe === null || $entry === null) {
            throw PipeConnectFailed::because('pipe_unavailable');
        }

        try {
            $tokens = $this->client->exchange($entry, $pipe, $this->secrets->clientSecret($pipe), $code, $flow->redirectUri, $flow->codeVerifier);
        } catch (PipeTokenRejected|PipeProviderUnavailable $e) {
            $this->audit->record(new AuditEvent(
                action: 'pipe.connection.failed',
                actorType: ActorType::User,
                actorId: $flow->userId,
                targetType: 'pipe',
                targetId: $pipe->id,
                context: ['provider' => $pipe->provider, 'reason' => $e instanceof PipeTokenRejected ? $e->error : 'provider_unavailable'],
            ));

            throw PipeConnectFailed::because('exchange_failed');
        }

        $connection = PipeConnection::query()
            ->where('pipe_id', $pipe->id)
            ->where('user_id', $flow->userId)
            ->first();

        $reconnected = $connection !== null;
        $connection = $this->storeTokens($pipe, $flow->userId, $tokens, $connection, $entry->assumedTokenLifetimeSeconds);

        $this->audit->record(new AuditEvent(
            action: 'pipe.connection.connected',
            actorType: ActorType::User,
            actorId: $flow->userId,
            targetType: 'pipe_connection',
            targetId: $connection->id,
            context: ['provider' => $pipe->provider, 'scopes' => $connection->scopes ?? [], 'reconnected' => $reconnected],
        ));

        $this->events->emit(new DomainEvent('pipe.connection.connected', [
            'connection_id' => $connection->id,
            'user_id' => $connection->user_id,
            'provider' => $connection->provider,
            'scopes' => $connection->scopes ?? [],
        ]));

        return $connection;
    }

    public function disconnect(string $connectionId, ?string $userId = null): bool
    {
        $this->environments()->requireEnvironment();

        $connection = $this->find($connectionId, $userId) ?? throw PipeConnectionNotFound::make();
        $pipe = Pipe::query()->whereKey($connection->pipe_id)->first();
        $entry = $pipe?->catalogueEntry();
        $revoked = false;

        if ($pipe !== null && $entry !== null && $entry->revocation !== null) {
            try {
                $access = $this->secrets->open($connection->access_secret_id, $connection->user_id, 'pipe.revoke');
                $refresh = $connection->refresh_secret_id === null
                    ? null
                    : $this->secrets->open($connection->refresh_secret_id, $connection->user_id, 'pipe.revoke');

                $revoked = $this->client->revoke($entry, $pipe, $this->secrets->clientSecret($pipe), $access, $refresh);
            } catch (Throwable) {
                // Revoking at the provider is best effort; forgetting the tokens here is not.
                $revoked = false;
            }
        }

        $this->secrets->revoke($connection->access_secret_id, $connection->user_id);
        $this->secrets->revoke($connection->refresh_secret_id, $connection->user_id);
        $connection->delete();

        $this->audit->record(new AuditEvent(
            action: 'pipe.connection.disconnected',
            actorType: $userId === null ? ActorType::System : ActorType::User,
            actorId: $userId,
            targetType: 'pipe_connection',
            targetId: $connection->id,
            context: ['provider' => $connection->provider, 'user_id' => $connection->user_id, 'revoked_at_provider' => $revoked],
        ));

        $this->events->emit(new DomainEvent('pipe.connection.disconnected', [
            'connection_id' => $connection->id,
            'user_id' => $connection->user_id,
            'provider' => $connection->provider,
            'revoked_at_provider' => $revoked,
        ]));

        return $revoked;
    }

    public function find(string $connectionId, ?string $userId = null): ?PipeConnection
    {
        $this->environments()->requireEnvironment();

        return PipeConnection::query()
            ->whereKey($connectionId)
            ->when($userId !== null, fn ($query) => $query->where('user_id', $userId))
            ->first();
    }

    public function forUser(string $userId): array
    {
        $this->environments()->requireEnvironment();

        return array_values(PipeConnection::query()->where('user_id', $userId)->orderBy('provider')->get()->all());
    }

    public function forPipe(string $pipeId): array
    {
        $this->environments()->requireEnvironment();

        return array_values(PipeConnection::query()->where('pipe_id', $pipeId)->orderBy('connected_at')->get()->all());
    }

    /**
     * Vault the tokens and write the connection. On a reconnect the existing vault secrets
     * are ROTATED in place (their ids, and so the broker grant, stay put); a refresh token
     * the provider no longer issues is revoked rather than left to rot.
     */
    private function storeTokens(Pipe $pipe, string $userId, PipeTokenSet $tokens, ?PipeConnection $connection, ?int $assumedLifetime): PipeConnection
    {
        if ($connection === null) {
            $connection = new PipeConnection;
            $connection->fill([
                'pipe_id' => $pipe->id,
                'provider' => $pipe->provider,
                'user_id' => $userId,
                'access_secret_id' => $this->secrets->store($pipe, $userId, 'access', $tokens->accessToken),
                'refresh_secret_id' => $tokens->refreshToken === null ? null : $this->secrets->store($pipe, $userId, 'refresh', $tokens->refreshToken),
            ]);
        } else {
            $this->secrets->rotate($connection->access_secret_id, $userId, $tokens->accessToken);

            if ($tokens->refreshToken !== null && $connection->refresh_secret_id !== null) {
                $this->secrets->rotate($connection->refresh_secret_id, $userId, $tokens->refreshToken);
            } elseif ($tokens->refreshToken !== null) {
                $connection->refresh_secret_id = $this->secrets->store($pipe, $userId, 'refresh', $tokens->refreshToken);
            } elseif ($connection->refresh_secret_id !== null) {
                $this->secrets->revoke($connection->refresh_secret_id, $userId);
                $connection->refresh_secret_id = null;
            }
        }

        $lifetime = $tokens->expiresIn ?? $assumedLifetime;

        $connection->fill([
            'status' => PipeConnectionStatus::Active,
            'scopes' => $tokens->scopes ?? $pipe->scopes,
            'metadata' => $tokens->metadata,
            'account_label' => $tokens->accountLabel ?? $connection->account_label,
            'access_expires_at' => $lifetime === null ? null : now()->addSeconds($lifetime),
            'connected_at' => now(),
            'last_refreshed_at' => null,
            'refresh_claimed_until' => null,
            'refresh_failures' => 0,
            'last_error' => null,
            'reauth_reason' => null,
        ]);
        $connection->save();

        return $connection;
    }
}
