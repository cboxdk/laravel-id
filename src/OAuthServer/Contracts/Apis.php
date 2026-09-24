<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidApiDefinition;
use Cbox\Id\OAuthServer\Models\Api;
use Cbox\Id\OAuthServer\Models\ApiScope;
use Cbox\Id\OAuthServer\ValueObjects\ApiAudience;
use Cbox\Id\OAuthServer\ValueObjects\ApiScopeDefinition;
use Cbox\Id\OAuthServer\ValueObjects\NewApi;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredScope;
use Illuminate\Support\Collection;

/**
 * The registry of APIs (resource servers) and the scopes they own.
 *
 * Management methods act in the AMBIENT environment, like every other registry here. The
 * three issuance reads at the bottom take the environment explicitly instead: the token
 * endpoint knows exactly which environment the client lives in, and binding that in the
 * WHERE clause means the answer cannot depend on whether scoping happens to be active.
 */
interface Apis
{
    /**
     * Register an API and its scopes in one step.
     *
     * @throws InvalidApiDefinition
     */
    public function register(NewApi $api): Api;

    public function find(string $id): ?Api;

    public function identifiedBy(string $identifier): ?Api;

    /**
     * Every API in the environment, ordered by name.
     *
     * @return Collection<int, Api>
     */
    public function all(): Collection;

    /**
     * The APIs one owner holds: an organization's, or with null the environment's own.
     *
     * @return Collection<int, Api>
     */
    public function ownedBy(?string $organizationId): Collection;

    /**
     * @throws InvalidApiDefinition
     */
    public function rename(Api $api, string $name): Api;

    /**
     * Link (or with null, unlink) the app whose declared roles/permissions this API
     * enforces. The app must have the same owner as the API.
     *
     * @throws InvalidApiDefinition
     */
    public function linkClient(Api $api, ?string $clientId): Api;

    /**
     * Add a scope to the API, or update its description and tenant-requestability when
     * the API already owns it.
     *
     * @throws InvalidApiDefinition
     */
    public function defineScope(Api $api, ApiScopeDefinition $scope): ApiScope;

    /**
     * Remove a scope. Clients holding the key keep it as free text — it simply stops
     * being a registered scope, and can no longer ride on this API's audience.
     */
    public function removeScope(Api $api, string $key): void;

    /**
     * Delete the API and its scopes. Tokens already minted for it keep their `aud` until
     * they expire; refreshes after this no longer resolve to it.
     */
    public function delete(Api $api): void;

    /**
     * The registered scopes among `$keys`, keyed by scope key. Keys no API owns are
     * absent from the result.
     *
     * @param  list<string>  $keys
     * @return array<string, RegisteredScope>
     */
    public function registeredScopes(string $environmentId, array $keys): array;

    /**
     * The registered API whose identifier is `$identifier`, if any.
     */
    public function audience(string $environmentId, string $identifier): ?ApiAudience;

    /**
     * The scopes ANY client in the environment may hold: those of environment-owned APIs
     * marked tenant-requestable. What discovery advertises and dynamic registration accepts.
     *
     * @return list<string>
     */
    public function publicScopes(string $environmentId): array;
}
