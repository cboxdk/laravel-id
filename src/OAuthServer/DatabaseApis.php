<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Cbox\Id\Kernel\Tenancy\Support\OwnerEnvironment;
use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\Enums\ProtocolScope;
use Cbox\Id\OAuthServer\Exceptions\InvalidApiDefinition;
use Cbox\Id\OAuthServer\Models\Api;
use Cbox\Id\OAuthServer\Models\ApiScope;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\ResourceIndicator;
use Cbox\Id\OAuthServer\ValueObjects\ApiAudience;
use Cbox\Id\OAuthServer\ValueObjects\ApiScopeDefinition;
use Cbox\Id\OAuthServer\ValueObjects\NewApi;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredScope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * The default {@see Apis}, over `oauth_apis` and `oauth_api_scopes`.
 */
class DatabaseApis implements Apis
{
    /**
     * RFC 6749 §3.3 `scope-token`: %x21 / %x23-5B / %x5D-7E — printable ASCII without
     * space, double quote or backslash.
     */
    private const SCOPE_TOKEN = '/^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/';

    public function register(NewApi $api): Api
    {
        if (! ResourceIndicator::isWellFormed($api->identifier)) {
            throw InvalidApiDefinition::identifier($api->identifier);
        }

        $name = $this->validName($api->name);

        // Same boundary every writer of an `organization_id` checks: the named owner
        // must live in THIS environment, which `EnvironmentScope` does not look at.
        OwnerEnvironment::assertLocal($api->organizationId, Api::class);

        if ($api->clientId !== null) {
            $this->assertLinkable($api->clientId, $api->organizationId);
        }

        if (Api::query()->where('identifier', $api->identifier)->exists()) {
            throw InvalidApiDefinition::identifierTaken($api->identifier);
        }

        // An API without the scopes it was described with is an API that audiences
        // tokens nobody can be granted anything for. All or nothing.
        return DB::transaction(function () use ($api, $name): Api {
            $model = Api::query()->create([
                'identifier' => $api->identifier,
                'name' => $name,
                'organization_id' => $api->organizationId,
                'client_id' => $api->clientId,
            ]);

            foreach ($api->scopes as $scope) {
                $this->defineScope($model, $scope);
            }

            return $model->load('scopes');
        });
    }

    public function find(string $id): ?Api
    {
        return Api::query()->with('scopes')->find($id);
    }

    public function identifiedBy(string $identifier): ?Api
    {
        return Api::query()->with('scopes')->where('identifier', $identifier)->first();
    }

    public function all(): Collection
    {
        return Api::query()->with('scopes')->orderBy('name')->get();
    }

    public function ownedBy(?string $organizationId): Collection
    {
        return Api::query()
            ->with('scopes')
            ->when(
                $organizationId === null,
                fn (Builder $q): Builder => $q->whereNull('organization_id'),
                fn (Builder $q): Builder => $q->where('organization_id', $organizationId),
            )
            ->orderBy('name')
            ->get();
    }

    public function rename(Api $api, string $name): Api
    {
        $api->forceFill(['name' => $this->validName($name)])->save();

        return $api;
    }

    public function linkClient(Api $api, ?string $clientId): Api
    {
        if ($clientId !== null) {
            $this->assertLinkable($clientId, $api->organization_id);
        }

        $api->forceFill(['client_id' => $clientId])->save();

        return $api;
    }

    public function defineScope(Api $api, ApiScopeDefinition $scope): ApiScope
    {
        if (preg_match(self::SCOPE_TOKEN, $scope->key) !== 1) {
            throw InvalidApiDefinition::scopeKey($scope->key);
        }

        if (ProtocolScope::isProtocol($scope->key)) {
            throw InvalidApiDefinition::reservedScope($scope->key);
        }

        // Bound to the API's own environment in the WHERE clause, not left to the ambient
        // scope: uniqueness is a property of that environment whether or not a provisioning
        // caller happens to have scoping suspended.
        $existing = ApiScope::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->where('environment_id', $api->environment_id)
            ->where('key', $scope->key)
            ->first();

        if ($existing !== null && $existing->api_id !== $api->id) {
            throw InvalidApiDefinition::scopeTaken($scope->key);
        }

        $row = $existing ?? new ApiScope([
            'environment_id' => $api->environment_id,
            'api_id' => $api->id,
            'key' => $scope->key,
        ]);

        $row->forceFill([
            'description' => $scope->description,
            'tenant_requestable' => $scope->tenantRequestable,
        ])->save();

        return $row;
    }

    public function removeScope(Api $api, string $key): void
    {
        ApiScope::query()->where('api_id', $api->id)->where('key', $key)->delete();
    }

    public function delete(Api $api): void
    {
        DB::transaction(function () use ($api): void {
            // Explicit rather than trusting the FK cascade: SQLite enforces foreign keys
            // only when the connection turned them on.
            ApiScope::query()->where('api_id', $api->id)->delete();
            $api->delete();
        });
    }

    public function registeredScopes(string $environmentId, array $keys): array
    {
        if ($keys === []) {
            return [];
        }

        $rows = ApiScope::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->where('environment_id', $environmentId)
            ->whereIn('key', array_values(array_unique($keys)))
            ->get();

        if ($rows->isEmpty()) {
            return [];
        }

        // The APIs are read under the SAME environment binding, so a scope row pointing
        // across the boundary finds no API and is dropped — corrupt is refused, not trusted.
        $apis = Api::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->where('environment_id', $environmentId)
            ->whereIn('id', $rows->pluck('api_id')->unique()->values()->all())
            ->get()
            ->keyBy('id');

        $registered = [];

        foreach ($rows as $row) {
            $api = $apis->get($row->api_id);

            if (! $api instanceof Api) {
                continue;
            }

            $registered[$row->key] = new RegisteredScope($row->key, $api->audience(), $row->tenant_requestable, $row->description);
        }

        return $registered;
    }

    public function audience(string $environmentId, string $identifier): ?ApiAudience
    {
        $api = Api::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->where('environment_id', $environmentId)
            ->where('identifier', $identifier)
            ->first();

        return $api?->audience();
    }

    public function publicScopes(string $environmentId): array
    {
        return array_values(ApiScope::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->where('oauth_api_scopes.environment_id', $environmentId)
            ->where('tenant_requestable', true)
            ->whereHas('api', fn (Builder $q): Builder => $q
                ->withoutGlobalScope(EnvironmentScope::class)
                ->where('environment_id', $environmentId)
                ->whereNull('organization_id'))
            ->orderBy('key')
            ->get()
            ->map(fn (ApiScope $scope): string => $scope->key)
            ->all());
    }

    private function validName(string $name): string
    {
        $name = trim($name);

        if ($name === '' || mb_strlen($name) > 120) {
            throw InvalidApiDefinition::name();
        }

        return $name;
    }

    /**
     * The linked app must exist here and share the API's owner. Otherwise a tenant could
     * name a platform app (or a peer's) as the enforcer of its own API and receive that
     * app's roles and permissions for its users in every token audienced to it.
     */
    private function assertLinkable(string $clientId, ?string $organizationId): void
    {
        $client = Client::query()->where('client_id', $clientId)->first();

        if ($client === null) {
            throw InvalidApiDefinition::unknownClient($clientId);
        }

        if ($client->organization_id !== $organizationId) {
            throw InvalidApiDefinition::clientOwnership($clientId);
        }
    }
}
