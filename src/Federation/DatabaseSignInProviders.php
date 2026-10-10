<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\SignInProviders;
use Cbox\Id\Federation\Enums\ConnectionStatus;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Models\ProviderOptOut;
use Illuminate\Database\Eloquent\Builder;

/**
 * The default {@see SignInProviders}: catalogue connections and opt-outs as rows, scoped to
 * the current environment by their global scope.
 *
 * Reads only the `provider`, owner and status COLUMNS to decide what is offered — never the
 * sealed configuration — so drawing a sign-in page costs three narrow queries however many
 * providers there are, and opens no secret.
 */
class DatabaseSignInProviders implements SignInProviders
{
    public function __construct(private readonly Connections $connections) {}

    public function offeredTo(?string $organizationId): array
    {
        /** @var array<string, Connection> $offered */
        $offered = [];

        $hidden = $organizationId === null ? [] : array_flip($this->notInheritedBy($organizationId));

        // 3. The environment's, unless the organization stopped inheriting it.
        foreach ($this->catalogue()->whereNull('organization_id')->get() as $connection) {
            $key = (string) $connection->provider;

            if ($connection->isActive() && ! isset($hidden[$key])) {
                $offered[$key] = $connection;
            }
        }

        if ($organizationId !== null) {
            // 1. The organization's own, which REPLACES the environment's for its key: a
            // provider of its own that is turned off removes the button rather than letting
            // the environment's credentials stand in. A DRAFT replaces nothing — it is a
            // half-saved form, not a decision.
            foreach ($this->catalogue()->where('organization_id', $organizationId)->get() as $connection) {
                $key = (string) $connection->provider;

                match ($connection->status) {
                    ConnectionStatus::Active => $offered[$key] = $connection,
                    ConnectionStatus::Inactive => $offered = array_diff_key($offered, [$key => true]),
                    ConnectionStatus::Draft => null,
                };
            }
        }

        ksort($offered);

        return array_values($offered);
    }

    public function environmentProviders(): array
    {
        return array_values($this->catalogue()->whereNull('organization_id')->orderBy('provider')->get()->all());
    }

    public function stopInheriting(string $organizationId, string $provider): bool
    {
        if ($this->opted($organizationId, $provider)->exists()) {
            return false;
        }

        ProviderOptOut::query()->create(['organization_id' => $organizationId, 'provider' => $provider]);

        return true;
    }

    public function resumeInheriting(string $organizationId, string $provider): bool
    {
        return $this->opted($organizationId, $provider)->delete() > 0;
    }

    public function notInheritedBy(string $organizationId): array
    {
        return array_values(ProviderOptOut::query()
            ->where('organization_id', $organizationId)
            ->orderBy('provider')
            ->get(['provider'])
            ->map(static fn (ProviderOptOut $optOut): string => $optOut->provider)
            ->all());
    }

    public function optOuts(): array
    {
        $byOrganization = [];

        foreach (ProviderOptOut::query()->orderBy('organization_id')->orderBy('provider')->get(['organization_id', 'provider']) as $row) {
            $byOrganization[$row->organization_id][] = $row->provider;
        }

        return $byOrganization;
    }

    public function create(
        ?string $organizationId,
        string $provider,
        ConnectionType $type,
        string $name,
        array $config,
        ?string $id = null,
    ): Connection {
        if ($id === null) {
            return $this->connections->create($organizationId, $type, $name, $config, provider: $provider);
        }

        // Only the default implementation can honour a reserved id; the contract hosts
        // implement has no such parameter, and adding one would break every one of them.
        if (! $this->connections instanceof ConnectionService) {
            throw InvalidAssertion::make('the bound Connections cannot create under a reserved id');
        }

        return $this->connections->create($organizationId, $type, $name, $config, provider: $provider, id: $id);
    }

    /** @return Builder<Connection> */
    private function catalogue(): Builder
    {
        return Connection::query()->whereNotNull('provider');
    }

    /** @return Builder<ProviderOptOut> */
    private function opted(string $organizationId, string $provider): Builder
    {
        return ProviderOptOut::query()->where('organization_id', $organizationId)->where('provider', $provider);
    }
}
