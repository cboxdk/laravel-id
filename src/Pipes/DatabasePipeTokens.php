<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Pipes\Contracts\PipeTokens;
use Cbox\Id\Pipes\Enums\PipeConnectionStatus;
use Cbox\Id\Pipes\Exceptions\PipeConnectionMissing;
use Cbox\Id\Pipes\Exceptions\PipeConnectionNotFound;
use Cbox\Id\Pipes\Exceptions\PipeLeaseDenied;
use Cbox\Id\Pipes\Exceptions\PipeProviderUnavailable;
use Cbox\Id\Pipes\Exceptions\PipeReauthorizationRequired;
use Cbox\Id\Pipes\Exceptions\PipeRefreshFailed;
use Cbox\Id\Pipes\Exceptions\PipeTokenRejected;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\Models\PipeGrant;
use Cbox\Id\Pipes\Support\PipeSecrets;
use Cbox\Id\Pipes\ValueObjects\PipeAccessToken;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Illuminate\Support\Sleep;

/**
 * Database-backed {@see PipeTokens}: the lease an app asks for, and the refresh behind it.
 *
 * ## Single-flight refresh
 *
 * A refresh token is a one-shot credential at every provider that rotates them (Slack,
 * Microsoft, Linear, Salesforce with rotation on): spend it twice and the second use is
 * treated as theft and revokes the whole grant. Two app instances leasing the same expiring
 * token at once, or a lease racing the background sweep, would do exactly that.
 *
 * So a refresh first CLAIMS the connection with one atomic UPDATE on
 * `refresh_claimed_until` — the same claim pattern the event relay uses, and one that needs
 * no shared cache or lock server to be correct across replicas. Whoever wins refreshes;
 * a lease that loses waits for the claim to clear and then reads the token the winner
 * stored; the sweep that loses simply moves on. A claim held by a process that died is
 * reclaimable once it lapses (`pipes.refresh_claim_seconds`).
 */
class DatabasePipeTokens implements PipeTokens
{
    use ResolvesEnvironment;

    public function __construct(
        private readonly PipeOAuthClient $client,
        private readonly PipeSecrets $secrets,
        private readonly AuditLog $audit,
        private readonly EventBus $events,
    ) {}

    public function lease(string $provider, string $userId, string $clientId, string $purpose): PipeAccessToken
    {
        $this->environments()->requireEnvironment();

        $pipe = Pipe::query()->where('provider', $provider)->first();
        $granted = $pipe !== null
            && $clientId !== ''
            && PipeGrant::query()->where('pipe_id', $pipe->id)->where('client_id', $clientId)->exists();

        // Uniform: no pipe, a disabled pipe and no grant are one refusal. The reason is
        // audited, never returned.
        if ($pipe === null || ! $pipe->enabled || ! $granted) {
            $this->audit->record(new AuditEvent(
                action: 'pipe.lease.denied',
                actorType: ActorType::Service,
                actorId: $clientId,
                targetType: 'pipe',
                targetId: $pipe?->id,
                context: [
                    'provider' => $provider,
                    'user_id' => $userId,
                    'purpose' => $purpose,
                    'reason' => match (true) {
                        $pipe === null => 'unknown_pipe',
                        ! $pipe->enabled => 'pipe_disabled',
                        default => 'no_grant',
                    },
                ],
            ));

            throw PipeLeaseDenied::make();
        }

        $connection = PipeConnection::query()->where('pipe_id', $pipe->id)->where('user_id', $userId)->first()
            ?? throw PipeConnectionMissing::make();

        if ($connection->isActive() && $connection->expiresWithin($this->skew())) {
            $connection = $this->refresh($connection->id);
        }

        if (! $connection->isActive()) {
            throw PipeReauthorizationRequired::make();
        }

        if ($connection->expiresWithin(0)) {
            // Still expired after a refresh attempt that did not throw: nothing usable.
            throw PipeRefreshFailed::because('token_expired');
        }

        try {
            $lease = $this->secrets->lease($connection->access_secret_id, $connection->user_id, 'pipe:'.$clientId.':'.$purpose);
        } catch (LeaseDenied) {
            // The vault refused its own broker — the secret was revoked under the
            // connection (erasure racing a lease). The connection cannot be used.
            throw PipeReauthorizationRequired::make();
        }

        $this->audit->record(new AuditEvent(
            action: 'pipe.token.leased',
            actorType: ActorType::Service,
            actorId: $clientId,
            targetType: 'pipe_connection',
            targetId: $connection->id,
            context: ['provider' => $provider, 'user_id' => $userId, 'purpose' => $purpose],
        ));

        return new PipeAccessToken(
            connectionId: $connection->id,
            provider: $connection->provider,
            userId: $connection->user_id,
            accessToken: $lease->secret,
            expiresAt: $connection->access_expires_at?->toDateTimeImmutable(),
            leaseExpiresAt: $lease->expiresAt,
            scopes: $connection->scopes ?? [],
            metadata: $connection->metadata ?? [],
        );
    }

    public function refresh(string $connectionId, bool $force = false, bool $wait = true): PipeConnection
    {
        return $this->refreshWithin($connectionId, $force ? null : $this->skew(), $wait);
    }

    public function refreshIfExpiring(string $connectionId, int $withinSeconds): PipeConnection
    {
        return $this->refreshWithin($connectionId, max(0, $withinSeconds), wait: false);
    }

    /**
     * @param  int|null  $within  refresh only when the token expires within this many seconds; null always refreshes
     */
    private function refreshWithin(string $connectionId, ?int $within, bool $wait): PipeConnection
    {
        $this->environments()->requireEnvironment();

        $connection = PipeConnection::query()->whereKey($connectionId)->first() ?? throw PipeConnectionNotFound::make();

        if (! $this->claim($connection)) {
            if (! $wait) {
                return $connection;
            }

            return $this->awaitOtherRefresh($connection);
        }

        try {
            // Re-read under the claim: another process may have refreshed between our read
            // and our claim, and spending the (possibly rotated) refresh token again would
            // be the double spend the claim exists to prevent.
            $connection->refresh();

            if (! $connection->isActive()) {
                return $connection;
            }

            if ($within !== null && ! $connection->expiresWithin($within)) {
                return $connection;
            }

            return $this->performRefresh($connection);
        } finally {
            PipeConnection::query()->whereKey($connection->id)->update(['refresh_claimed_until' => null]);
            $connection->refresh_claimed_until = null;
        }
    }

    private function performRefresh(PipeConnection $connection): PipeConnection
    {
        $pipe = Pipe::query()->whereKey($connection->pipe_id)->first();
        $entry = $pipe?->catalogueEntry();

        if ($pipe === null || $entry === null) {
            return $this->needsReauth($connection, 'pipe_unavailable');
        }

        if (! $connection->canRefresh()) {
            // Nothing to refresh with. Only dead once it has actually expired — a token
            // with a few minutes left is still worth handing out.
            return $connection->expiresWithin(0) ? $this->needsReauth($connection, 'no_refresh_token') : $connection;
        }

        try {
            $refreshToken = $this->secrets->open((string) $connection->refresh_secret_id, $connection->user_id, 'pipe.refresh');
            $tokens = $this->client->refresh($entry, $pipe, $this->secrets->clientSecret($pipe), $refreshToken);
        } catch (LeaseDenied) {
            return $this->needsReauth($connection, 'refresh_token_unavailable');
        } catch (PipeTokenRejected $e) {
            if ($e->revokesTheGrant()) {
                return $this->needsReauth($connection, $e->error);
            }

            $this->transientFailure($connection, $e->error);
        } catch (PipeProviderUnavailable) {
            $this->transientFailure($connection, 'provider_unavailable');
        }

        $this->secrets->rotate($connection->access_secret_id, $connection->user_id, $tokens->accessToken);

        if ($tokens->refreshToken !== null) {
            // Rotated: the old one is now spent (or about to be) at the provider.
            $this->secrets->rotate((string) $connection->refresh_secret_id, $connection->user_id, $tokens->refreshToken);
        }

        $lifetime = $tokens->expiresIn ?? $entry->assumedTokenLifetimeSeconds;

        $connection->fill([
            'access_expires_at' => $lifetime === null ? null : now()->addSeconds($lifetime),
            'scopes' => $tokens->scopes ?? $connection->scopes,
            'metadata' => array_merge($connection->metadata ?? [], $tokens->metadata),
            'last_refreshed_at' => now(),
            'refresh_failures' => 0,
            'last_error' => null,
        ]);
        $connection->save();

        $this->audit->record(new AuditEvent(
            action: 'pipe.connection.refreshed',
            targetType: 'pipe_connection',
            targetId: $connection->id,
            context: ['provider' => $connection->provider, 'user_id' => $connection->user_id, 'rotated_refresh_token' => $tokens->refreshToken !== null],
        ));

        return $connection;
    }

    /**
     * @throws PipeRefreshFailed always
     */
    private function transientFailure(PipeConnection $connection, string $reason): never
    {
        $connection->refresh_failures++;
        $connection->last_error = mb_substr($reason, 0, 64);
        $connection->save();

        $this->audit->record(new AuditEvent(
            action: 'pipe.connection.refresh_failed',
            targetType: 'pipe_connection',
            targetId: $connection->id,
            context: ['provider' => $connection->provider, 'user_id' => $connection->user_id, 'reason' => $reason, 'failures' => $connection->refresh_failures],
        ));

        throw PipeRefreshFailed::because($reason);
    }

    private function needsReauth(PipeConnection $connection, string $reason): PipeConnection
    {
        $connection->status = PipeConnectionStatus::NeedsReauth;
        $connection->reauth_reason = mb_substr($reason, 0, 64);
        $connection->save();

        $this->audit->record(new AuditEvent(
            action: 'pipe.connection.needs_reauth',
            targetType: 'pipe_connection',
            targetId: $connection->id,
            context: ['provider' => $connection->provider, 'user_id' => $connection->user_id, 'reason' => $reason],
        ));

        $this->events->emit(new DomainEvent('pipe.connection.needs_reauth', [
            'connection_id' => $connection->id,
            'user_id' => $connection->user_id,
            'provider' => $connection->provider,
            'reason' => $connection->reauth_reason,
        ]));

        return $connection;
    }

    /** One atomic UPDATE: true only for the process that took the claim. */
    private function claim(PipeConnection $connection): bool
    {
        $now = now();

        return PipeConnection::query()
            ->whereKey($connection->id)
            ->where(fn ($query) => $query->whereNull('refresh_claimed_until')->orWhere('refresh_claimed_until', '<', $now))
            ->update(['refresh_claimed_until' => $now->copy()->addSeconds($this->intConfig('refresh_claim_seconds', 30))]) === 1;
    }

    /**
     * Another process is refreshing this connection: wait for it to finish and use what it
     * stored, rather than spend the refresh token a second time.
     *
     * @throws PipeRefreshFailed when it does not finish within `pipes.refresh_wait_milliseconds`
     */
    private function awaitOtherRefresh(PipeConnection $connection): PipeConnection
    {
        $deadline = microtime(true) + $this->intConfig('refresh_wait_milliseconds', 5000) / 1000;

        do {
            Sleep::usleep(100_000);
            $connection->refresh();

            $claimed = $connection->refresh_claimed_until !== null && $connection->refresh_claimed_until->isFuture();

            if (! $claimed) {
                return $connection;
            }
        } while (microtime(true) < $deadline);

        throw PipeRefreshFailed::because('refresh_in_progress');
    }

    private function skew(): int
    {
        return $this->intConfig('lease_refresh_skew_seconds', 60);
    }

    private function intConfig(string $key, int $default): int
    {
        $value = config('cbox-id.pipes.'.$key, $default);

        return is_numeric($value) ? max(0, (int) $value) : $default;
    }
}
