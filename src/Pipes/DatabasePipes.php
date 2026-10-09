<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Pipes\Contracts\Pipes;
use Cbox\Id\Pipes\Exceptions\InvalidPipeConfiguration;
use Cbox\Id\Pipes\Exceptions\PipeNotFound;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\Models\PipeGrant;
use Cbox\Id\Pipes\Support\PipeSecrets;
use Illuminate\Support\Str;

/**
 * Database-backed {@see Pipes}.
 *
 * Every write requires an ambient environment (hard tenancy) and is audited — with the
 * provider, the client id and the scopes, never the client secret. The secret is sealed
 * on the way in and there is no way back out through here.
 */
class DatabasePipes implements Pipes
{
    use ResolvesEnvironment;

    public function __construct(
        private readonly PipeSecrets $secrets,
        private readonly AuditLog $audit,
    ) {}

    public function configure(string $provider, string $clientId, string $clientSecret, ?array $scopes = null, array $parameters = []): Pipe
    {
        $this->environments()->requireEnvironment();

        $entry = PipeProviderCatalog::find($provider) ?? throw InvalidPipeConfiguration::unknownProvider($provider);

        if ($this->forProvider($provider) !== null) {
            throw InvalidPipeConfiguration::alreadyConfigured($provider);
        }

        $pipe = new Pipe;
        // Assigned before sealing: the secret's AEAD context is the row id.
        $pipe->id = (string) Str::ulid();
        $pipe->fill([
            'provider' => $entry->key,
            'client_id' => $this->required($clientId, 'client ID'),
            'scopes' => $this->scopes($scopes ?? $entry->defaultScopes),
            'parameters' => $entry->parameterValues($parameters),
            'enabled' => true,
        ]);
        $this->secrets->sealClientSecret($pipe, $this->required($clientSecret, 'client secret'));
        $pipe->save();

        $this->audit->record(new AuditEvent(
            action: 'pipe.configured',
            targetType: 'pipe',
            targetId: $pipe->id,
            context: ['provider' => $pipe->provider, 'client_id' => $pipe->client_id, 'scopes' => $pipe->scopes],
        ));

        return $pipe;
    }

    public function update(string $pipeId, ?string $clientId = null, ?string $clientSecret = null, ?array $scopes = null, ?array $parameters = null, ?bool $enabled = null): Pipe
    {
        $this->environments()->requireEnvironment();

        $pipe = $this->find($pipeId) ?? throw PipeNotFound::forId($pipeId);
        $entry = $pipe->catalogueEntry() ?? throw InvalidPipeConfiguration::unknownProvider($pipe->provider);
        $changed = [];

        if ($clientId !== null) {
            $pipe->client_id = $this->required($clientId, 'client ID');
            $changed[] = 'client_id';
        }

        if ($clientSecret !== null) {
            $this->secrets->sealClientSecret($pipe, $this->required($clientSecret, 'client secret'));
            $changed[] = 'client_secret';
        }

        if ($scopes !== null) {
            $pipe->scopes = $this->scopes($scopes);
            $changed[] = 'scopes';
        }

        if ($parameters !== null) {
            $pipe->parameters = $entry->parameterValues($parameters);
            $changed[] = 'parameters';
        }

        if ($enabled !== null) {
            $pipe->enabled = $enabled;
            $changed[] = 'enabled';
        }

        $pipe->save();

        $this->audit->record(new AuditEvent(
            action: 'pipe.updated',
            targetType: 'pipe',
            targetId: $pipe->id,
            // The NAMES of what changed — for the secret, that it changed and nothing more.
            context: ['provider' => $pipe->provider, 'changed' => $changed, 'scopes' => $pipe->scopes, 'enabled' => $pipe->enabled],
        ));

        return $pipe;
    }

    public function remove(string $pipeId): void
    {
        $this->environments()->requireEnvironment();

        $pipe = $this->find($pipeId) ?? throw PipeNotFound::forId($pipeId);

        $connections = PipeConnection::query()->where('pipe_id', $pipe->id)->get();

        foreach ($connections as $connection) {
            $this->secrets->revoke($connection->access_secret_id, $connection->user_id);
            $this->secrets->revoke($connection->refresh_secret_id, $connection->user_id);
        }

        PipeConnection::query()->where('pipe_id', $pipe->id)->delete();
        PipeGrant::query()->where('pipe_id', $pipe->id)->delete();
        $pipe->delete();

        $this->audit->record(new AuditEvent(
            action: 'pipe.removed',
            targetType: 'pipe',
            targetId: $pipe->id,
            context: ['provider' => $pipe->provider, 'connections' => $connections->count()],
        ));
    }

    public function find(string $pipeId): ?Pipe
    {
        $this->environments()->requireEnvironment();

        return Pipe::query()->whereKey($pipeId)->first();
    }

    public function forProvider(string $provider): ?Pipe
    {
        $this->environments()->requireEnvironment();

        return Pipe::query()->where('provider', $provider)->first();
    }

    public function all(): array
    {
        $this->environments()->requireEnvironment();

        return array_values(Pipe::query()->orderBy('provider')->get()->all());
    }

    public function grant(string $pipeId, string $clientId): PipeGrant
    {
        $this->environments()->requireEnvironment();

        $pipe = $this->find($pipeId) ?? throw PipeNotFound::forId($pipeId);
        $clientId = $this->required($clientId, 'client ID');

        $existing = PipeGrant::query()->where('pipe_id', $pipe->id)->where('client_id', $clientId)->first();

        if ($existing !== null) {
            return $existing;
        }

        $grant = PipeGrant::query()->create(['pipe_id' => $pipe->id, 'client_id' => $clientId]);

        $this->audit->record(new AuditEvent(
            action: 'pipe.grant.created',
            targetType: 'pipe',
            targetId: $pipe->id,
            context: ['provider' => $pipe->provider, 'client_id' => $clientId],
        ));

        return $grant;
    }

    public function revokeGrant(string $pipeId, string $clientId): void
    {
        $this->environments()->requireEnvironment();

        $pipe = $this->find($pipeId);

        if ($pipe === null) {
            return;
        }

        $deleted = PipeGrant::query()->where('pipe_id', $pipe->id)->where('client_id', $clientId)->delete();

        if ($deleted === 0) {
            return;
        }

        $this->audit->record(new AuditEvent(
            action: 'pipe.grant.revoked',
            targetType: 'pipe',
            targetId: $pipe->id,
            context: ['provider' => $pipe->provider, 'client_id' => $clientId],
        ));
    }

    public function grantedClients(string $pipeId): array
    {
        $this->environments()->requireEnvironment();

        return array_values(PipeGrant::query()
            ->where('pipe_id', $pipeId)
            ->orderBy('client_id')
            ->get()
            ->map(static fn (PipeGrant $grant): string => $grant->client_id)
            ->all());
    }

    public function isGranted(string $pipeId, string $clientId): bool
    {
        $this->environments()->requireEnvironment();

        return $clientId !== '' && PipeGrant::query()->where('pipe_id', $pipeId)->where('client_id', $clientId)->exists();
    }

    private function required(string $value, string $field): string
    {
        $value = trim($value);

        return $value === '' ? throw InvalidPipeConfiguration::blank($field) : $value;
    }

    /**
     * Trimmed, de-duplicated, no blanks — and nothing that could smuggle a second
     * parameter into the authorization URL.
     *
     * @param  array<mixed>  $scopes
     * @return list<string>
     */
    private function scopes(array $scopes): array
    {
        $clean = [];

        foreach ($scopes as $scope) {
            if (! is_string($scope)) {
                throw InvalidPipeConfiguration::blank('scope');
            }

            $scope = trim($scope);

            if ($scope === '') {
                continue;
            }

            // RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). No spaces, no
            // quotes, no backslashes — and, since some providers split on them, no commas.
            if (preg_match('/^[\x21\x23-\x2B\x2D-\x5B\x5D-\x7E]+$/', $scope) !== 1) {
                throw new InvalidPipeConfiguration("The scope [{$scope}] is not a valid OAuth scope.");
            }

            if (! in_array($scope, $clean, true)) {
                $clean[] = $scope;
            }
        }

        return $clean;
    }
}
