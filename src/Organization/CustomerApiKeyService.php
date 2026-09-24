<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesTenant;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\Organization\Contracts\CustomerApiKeys;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\ApiKeyRefusal;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Exceptions\CustomerApiKeyRefused;
use Cbox\Id\Organization\Exceptions\InvalidApiKeyPrefix;
use Cbox\Id\Organization\Models\CustomerApiKey;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\ValueObjects\ApiKeyActor;
use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;
use Cbox\Id\Organization\ValueObjects\ApiKeyVerification;
use Cbox\Id\Organization\ValueObjects\IssuedCustomerApiKey;
use Cbox\Id\Organization\ValueObjects\NewCustomerApiKey;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Eloquent-backed customer API keys, built on the user API token machinery: the same
 * table, the same SHA-256-at-rest, looked-up-by-hash discipline (a wrong key simply
 * does not match — no timing oracle), the same non-secret listing fragment.
 *
 * TWO CAPS, and both matter. Issuance refuses any permission the holder does not hold
 * for the app right now. Verification then intersects the key's permissions with what
 * the holder holds AT THAT MOMENT, so the issuance check is not the only thing standing
 * between a demoted member and the access they used to have: a key is a ceiling, never
 * a grant of its own.
 */
class CustomerApiKeyService implements CustomerApiKeys
{
    // Lazy per-call resolution of the ambient tenant — see UserApiTokenService: this is a
    // singleton and TenantContext is scoped.
    use ResolvesTenant;

    /**
     * How long a `last_used_at` write is skipped after the last one, in seconds — the
     * window every other key in the package uses. Verification is a hot path; the column
     * tells a holder whether a key is still wired into something, not a request count.
     */
    private const TOUCH_THROTTLE_SECONDS = 60;

    /** Characters of the plaintext kept for listings, after the prefix and its underscore. */
    private const FRAGMENT_RANDOM_CHARACTERS = 4;

    private const MAX_NAME_LENGTH = 255;

    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly AccessChecker $access,
        private readonly Memberships $memberships,
        private readonly Organizations $organizations,
        private readonly Subjects $subjects,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function setPrefix(string $clientId, ?ApiKeyPrefix $prefix): void
    {
        $client = $this->clients->byClientId($clientId)
            ?? throw CustomerApiKeyRefused::because(ApiKeyRefusal::UnknownClient, "No app with client id [{$clientId}] in this environment.");

        if ($prefix !== null && Client::query()
            ->where('api_key_prefix', $prefix->value)
            ->whereKeyNot($client->getKey())
            ->exists()) {
            throw InvalidApiKeyPrefix::taken($prefix->value);
        }

        try {
            $client->forceFill(['api_key_prefix' => $prefix?->value])->save();
        } catch (UniqueConstraintViolationException) {
            // Two apps declaring the same prefix at the same moment: the index decides.
            throw InvalidApiKeyPrefix::taken((string) $prefix?->value);
        }

        $this->audit->record(new AuditEvent(
            action: 'client.api_key_prefix_set',
            actorType: ActorType::System,
            organizationId: $client->organization_id,
            targetType: 'oauth_client',
            targetId: $client->client_id,
            context: ['api_key_prefix' => $prefix?->value],
        ));
    }

    public function issue(NewCustomerApiKey $input, ?ApiKeyActor $actor = null): IssuedCustomerApiKey
    {
        $client = $this->clients->byClientId($input->clientId)
            ?? throw CustomerApiKeyRefused::because(ApiKeyRefusal::UnknownClient, "No app with client id [{$input->clientId}] in this environment.");

        $prefix = $client->api_key_prefix === null ? null : ApiKeyPrefix::tryFrom($client->api_key_prefix);

        if ($prefix === null) {
            throw CustomerApiKeyRefused::because(ApiKeyRefusal::KeysNotEnabled, "App [{$client->client_id}] has not declared an API key prefix, so it issues no API keys to its users.");
        }

        $name = $this->name($input->name);
        $permissions = $this->permissions($input->permissions);

        if ($input->expiresAt !== null && $input->expiresAt->getTimestamp() <= now()->getTimestamp()) {
            throw CustomerApiKeyRefused::because(ApiKeyRefusal::ExpiryInPast, 'An API key expiry must be in the future.');
        }

        $refusal = $this->holderRefusal(
            $input->organizationId,
            $input->userId,
            $this->memberships->of($input->organizationId, $input->userId),
        );

        if ($refusal !== null) {
            throw CustomerApiKeyRefused::because($refusal, sprintf(
                'User [%s] cannot hold an API key in organization [%s]: %s.',
                $input->userId,
                $input->organizationId,
                $refusal->value,
            ));
        }

        // THE ISSUANCE CAP. The same resolution a token for this app would be stamped
        // with — org-wide roles plus the app's own, never another app's — so a key can
        // carry nothing its holder could not have been issued in an access token.
        $held = $this->access->forToken($input->userId, $input->organizationId, $client->client_id)->permissions;
        $missing = array_values(array_diff($permissions, $held));

        if ($missing !== []) {
            throw CustomerApiKeyRefused::permissionsNotHeld($missing, $client->client_id);
        }

        $plaintext = $prefix->value.'_'.Str::random(ApiKeyPrefix::RANDOM_LENGTH);
        $actor ??= ApiKeyActor::user($input->userId);

        $key = $this->tenant()->runAs(GenericTenant::of($input->organizationId), fn (): CustomerApiKey => DB::transaction(function () use ($input, $client, $name, $permissions, $plaintext, $prefix, $actor): CustomerApiKey {
            $key = new CustomerApiKey;
            $key->fill([
                'user_id' => $input->userId,
                'client_id' => $client->client_id,
                'name' => $name,
                'prefix' => substr($plaintext, 0, strlen($prefix->value) + 1 + self::FRAGMENT_RANDOM_CHARACTERS),
                'token_hash' => $this->hash($plaintext),
                'permissions' => $permissions,
                'expires_at' => $input->expiresAt,
            ]);
            $key->save();

            $this->emitAndAudit($key, 'api_key.created', $actor, [
                'name' => $name,
                'permissions' => $permissions,
                'prefix' => $key->prefix,
                'expires_at' => $key->expires_at?->toIso8601ZuluString(),
            ]);

            return $key;
        }));

        return new IssuedCustomerApiKey($key, $plaintext);
    }

    public function verify(Client $caller, string $plaintext): ApiKeyVerification
    {
        // Cheap shape check before touching the database: a string that cannot be a key
        // never costs a query.
        if (! ApiKeyPrefix::isKeyShaped($plaintext)) {
            return ApiKeyVerification::inactive();
        }

        // The binding to the caller is IN THE WHERE CLAUSE, not a comparison after the
        // read. A key of another app is not "found, then refused" — it is never found,
        // so no later refactor of the checks below can let it through.
        //
        // Unscoped on the TENANT only: verification precedes any organization context,
        // and the key names its own. The environment scope stays on.
        $key = $this->tenant()->withoutScope(
            fn (): ?CustomerApiKey => $this->boundToCaller(CustomerApiKey::query(), $caller)
                ->where('token_hash', $this->hash($plaintext))
                ->first(),
        );

        if ($key === null || ! $key->isActive()) {
            return ApiKeyVerification::inactive();
        }

        $membership = $this->memberships->of($key->organization_id, $key->user_id);

        if ($membership === null || $this->holderRefusal($key->organization_id, $key->user_id, $membership) !== null) {
            return ApiKeyVerification::inactive();
        }

        // A key predating the holder's CURRENT membership belongs to a membership that
        // ended. Removing a member deletes the row (and their role assignments, for the
        // same reason); re-adding them later must not bring back keys nobody re-issued.
        if ($membership->created_at !== null && $key->created_at !== null && $membership->created_at->gt($key->created_at)) {
            return ApiKeyVerification::inactive();
        }

        // THE RE-CAP. What the holder holds for this app NOW, intersected with the key's
        // ceiling — a demotion takes effect on the next request, not at the next reissue.
        $held = $this->access->forToken($key->user_id, $key->organization_id, $key->client_id)->permissions;
        $permissions = array_values(array_intersect($key->permissions, $held));

        $this->touch($key);

        return new ApiKeyVerification(
            active: true,
            keyId: $key->id,
            userId: $key->user_id,
            organizationId: $key->organization_id,
            organizationRole: $membership->role,
            permissions: $permissions,
            clientId: $key->client_id,
            expiresAt: $key->expires_at,
        );
    }

    public function find(string $keyId): ?CustomerApiKey
    {
        return $this->tenant()->withoutScope(
            fn (): ?CustomerApiKey => CustomerApiKey::query()->whereKey($keyId)->first(),
        );
    }

    public function revoke(string $keyId, ApiKeyActor $actor): bool
    {
        $key = $this->find($keyId);

        if ($key === null) {
            return false;
        }

        return $this->tenant()->runAs(GenericTenant::of($key->organization_id), fn (): bool => DB::transaction(function () use ($key, $actor): bool {
            // Conditional on still being live, so two concurrent revocations record one
            // revocation, one audit entry and one webhook — not two.
            $revoked = CustomerApiKey::query()
                ->whereKey($key->id)
                ->whereNull('revoked_at')
                ->update(['revoked_at' => now(), 'updated_at' => now()]);

            if ($revoked === 0) {
                return false;
            }

            $this->emitAndAudit($key, 'api_key.revoked', $actor, [
                'name' => $key->name,
                'revoked_by' => ['type' => $actor->type->value, 'id' => $actor->id],
            ]);

            return true;
        }));
    }

    public function forUser(string $organizationId, string $userId, ?string $clientId = null): Collection
    {
        // ULIDs are monotonic: ordering by id is newest-first and deterministic even for
        // keys minted within the same clock tick.
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => CustomerApiKey::query()
                ->where('user_id', $userId)
                ->when($clientId !== null, fn (Builder $query) => $query->where('client_id', $clientId))
                ->orderByDesc('id')
                ->get(),
        );
    }

    public function forOrganization(string $organizationId, ?string $clientId = null): Collection
    {
        return $this->tenant()->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => CustomerApiKey::query()
                ->when($clientId !== null, fn (Builder $query) => $query->where('client_id', $clientId))
                ->orderByDesc('id')
                ->get(),
        );
    }

    /**
     * Constrain a key query to the keys `$caller` may verify: today, keys bound to the
     * caller's own `client_id`.
     *
     * THE EXTENSION POINT for resource servers. When an API (resource server) entity
     * exists whose `client_id` names the app whose permissions it enforces, a key issued
     * for that API is bound to the same `client_id`, and this constraint already admits
     * it. Should keys ever bind to an API by its own id instead, widen the constraint
     * HERE — `->orWhereIn('api_id', <ids of APIs whose client_id is the caller>)` — and
     * keep it a WHERE clause: a check after the read cannot fail the way this can.
     *
     * @param  Builder<CustomerApiKey>  $query
     * @return Builder<CustomerApiKey>
     */
    protected function boundToCaller(Builder $query, Client $caller): Builder
    {
        return $query->where('client_id', $caller->client_id);
    }

    /**
     * Why this holder may not hold (or use) a key in this organization right now, or
     * null when they may: an active member, of an active organization, with an active
     * account.
     */
    private function holderRefusal(string $organizationId, string $userId, ?Membership $membership): ?ApiKeyRefusal
    {
        $organization = $this->organizations->find($organizationId);

        if ($organization === null || $organization->status->revokesAccess()) {
            return ApiKeyRefusal::OrganizationInactive;
        }

        if ($membership === null || $membership->status !== MembershipStatus::Active) {
            return ApiKeyRefusal::NotAMember;
        }

        if (! $this->subjects->isActive($userId)) {
            return ApiKeyRefusal::HolderInactive;
        }

        return null;
    }

    private function name(?string $name): ?string
    {
        if ($name === null) {
            return null;
        }

        $name = trim($name);

        if ($name === '') {
            return null;
        }

        if (mb_strlen($name) > self::MAX_NAME_LENGTH) {
            throw CustomerApiKeyRefused::because(ApiKeyRefusal::InvalidInput, 'An API key name is at most '.self::MAX_NAME_LENGTH.' characters.');
        }

        return $name;
    }

    /**
     * @param  list<string>  $permissions
     * @return list<string>
     */
    private function permissions(array $permissions): array
    {
        $clean = [];

        foreach ($permissions as $permission) {
            if ($permission === '' || mb_strlen($permission) > 255) {
                throw CustomerApiKeyRefused::because(ApiKeyRefusal::InvalidInput, 'A permission name must be 1 to 255 characters.');
            }

            $clean[$permission] = true;
        }

        return array_keys($clean);
    }

    /**
     * Stamp `last_used_at`, at most once per throttle window. The window is part of the
     * UPDATE's own WHERE clause, so a burst of concurrent verifications writes the row
     * once rather than racing to write it many times.
     */
    private function touch(CustomerApiKey $key): void
    {
        if ($key->last_used_at !== null && $key->last_used_at->diffInSeconds(now()) < self::TOUCH_THROTTLE_SECONDS) {
            return;
        }

        $this->tenant()->runAs(GenericTenant::of($key->organization_id), fn (): int => CustomerApiKey::query()
            ->whereKey($key->id)
            ->where(fn (Builder $query) => $query
                ->whereNull('last_used_at')
                ->orWhere('last_used_at', '<=', now()->subSeconds(self::TOUCH_THROTTLE_SECONDS)))
            ->update(['last_used_at' => now()]));
    }

    private function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function emitAndAudit(CustomerApiKey $key, string $action, ApiKeyActor $actor, array $context): void
    {
        $this->events->emit(new DomainEvent($action, [
            'key_id' => $key->id,
            'user_id' => $key->user_id,
            'client_id' => $key->client_id,
        ] + $context, $key->organization_id));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: $actor->type,
            actorId: $actor->id,
            organizationId: $key->organization_id,
            targetType: 'customer_api_key',
            targetId: $key->id,
            context: ['client_id' => $key->client_id, 'user_id' => $key->user_id] + $context,
        ));
    }
}
