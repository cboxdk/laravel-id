<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Carbon\CarbonImmutable;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\Organization\Contracts\ResourceAccess;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\Exceptions\TokenScopeExceedsIssuerRole;
use Cbox\Id\Organization\Models\UserApiToken;
use Cbox\Id\Organization\ValueObjects\IssuedUserApiToken;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Eloquent-backed user API tokens. Follows the platform's key discipline: a
 * high-entropy `cbid_pat_` token, SHA-256-hashed at rest, looked up by hash so
 * a wrong token simply doesn't match (no timing oracle), with a non-secret
 * prefix fragment for listings.
 *
 * The issuer cap lives HERE, not in an HTTP layer: issuing resolves the
 * user's effective role and refuses a scope the role couldn't hold — a token
 * must never out-rank the member minting it, on any code path.
 */
class UserApiTokenService implements UserApiTokens
{
    /** Brand root `cbid` + plane marker `pat` (a user-bound personal token). */
    private const PREFIX = 'cbid_pat_';

    /** A token issued without an explicit expiry is never open-ended. */
    private const DEFAULT_TTL_DAYS = 90;

    public function __construct(
        private readonly TenantContext $tenant,
        private readonly ResourceAccess $access,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function issue(
        string $organizationId,
        string $userId,
        string $name,
        TokenScope $scope,
        ?array $resourceFamilies = null,
        ?DateTimeInterface $expiresAt = null,
    ): IssuedUserApiToken {
        // The cap: resolve the issuer's effective role at org level. No active
        // membership means no tokens at all — a stranger mints nothing.
        $role = $this->access->effectiveRole($organizationId, $userId);

        if ($role === null || ! $scope->issuableBy($role)) {
            throw TokenScopeExceedsIssuerRole::make($organizationId, $scope, $role);
        }

        $plaintext = self::PREFIX.Str::random(48);

        $configured = config('cbox-id.user_api_tokens.default_ttl_days');
        $ttlDays = is_numeric($configured) ? (int) $configured : self::DEFAULT_TTL_DAYS;
        $expiry = $expiresAt ?? CarbonImmutable::now()->addDays($ttlDays);

        $token = $this->tenant->runAs(GenericTenant::of($organizationId), fn (): UserApiToken => DB::transaction(function () use ($organizationId, $userId, $name, $scope, $resourceFamilies, $expiry, $plaintext): UserApiToken {
            $token = new UserApiToken;
            $token->fill([
                'user_id' => $userId,
                'name' => $name,
                'prefix' => substr($plaintext, 0, 12),
                'token_hash' => $this->hash($plaintext),
                'scope' => $scope,
                'resource_families' => $resourceFamilies === [] ? null : $resourceFamilies,
                'expires_at' => $expiry,
            ]);
            $token->save();

            $this->emitAndAudit($organizationId, $token, 'organization.api_token_issued', [
                'name' => $name,
                'scope' => $scope->value,
            ]);

            return $token;
        }));

        return new IssuedUserApiToken($token, $plaintext);
    }

    public function resolve(string $plaintext): ?UserApiToken
    {
        // Cheap shape check before touching the database.
        if (! str_starts_with($plaintext, self::PREFIX)) {
            return null;
        }

        // Authentication happens before any tenant context exists, so the
        // lookup runs unscoped; the returned token carries its organization.
        $token = $this->tenant->withoutScope(
            fn (): ?UserApiToken => UserApiToken::query()->where('token_hash', $this->hash($plaintext))->first(),
        );

        if ($token === null || ! $token->isActive()) {
            return null;
        }

        $this->tenant->runAs(
            GenericTenant::of($token->organization_id),
            fn () => $token->forceFill(['last_used_at' => now()])->save(),
        );

        return $token;
    }

    public function revoke(string $organizationId, string $tokenId): void
    {
        $this->tenant->runAs(GenericTenant::of($organizationId), fn () => DB::transaction(function () use ($organizationId, $tokenId): void {
            $token = UserApiToken::query()->whereKey($tokenId)->whereNull('revoked_at')->first();

            if ($token === null) {
                return;
            }

            $token->forceFill(['revoked_at' => now()])->save();

            $this->emitAndAudit($organizationId, $token, 'organization.api_token_revoked', [
                'name' => $token->name,
            ]);
        }));
    }

    public function forUser(string $organizationId, string $userId): Collection
    {
        // ULIDs are monotonic: ordering by id is newest-first and deterministic
        // even for tokens minted within the same clock tick.
        return $this->tenant->runAs(
            GenericTenant::of($organizationId),
            fn (): Collection => UserApiToken::query()
                ->where('user_id', $userId)
                ->orderByDesc('id')
                ->get(),
        );
    }

    private function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function emitAndAudit(string $organizationId, UserApiToken $token, string $action, array $context): void
    {
        $this->events->emit(new DomainEvent($action, ['token_id' => $token->id, 'user_id' => $token->user_id] + $context, $organizationId));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::User,
            actorId: $token->user_id,
            organizationId: $organizationId,
            targetType: 'user_api_token',
            targetId: $token->id,
            context: $context,
        ));
    }
}
