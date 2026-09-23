<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\AccessControl\Contracts\StaffAccess;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\SupportSessions;
use Cbox\Id\OAuthServer\Enums\SupportActorKind;
use Cbox\Id\OAuthServer\Enums\SupportSessionRefusal;
use Cbox\Id\OAuthServer\Exceptions\SupportSessionRefused;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\AuthorizationCode;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\SupportSession;
use Cbox\Id\OAuthServer\Support\GrantPolicy;
use Cbox\Id\OAuthServer\ValueObjects\ActingParty;
use Cbox\Id\OAuthServer\ValueObjects\NewSupportSession;
use Cbox\Id\OAuthServer\ValueObjects\StartedSupportSession;
use Cbox\Id\OAuthServer\ValueObjects\SupportCodeRequest;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Enums\OrganizationStatus;
use Illuminate\Support\Facades\DB;

/**
 * {@see SupportSessions} over the database, minting codes through
 * {@see AuthorizationCodes} so a support session's sign-in is an ordinary code exchange
 * for the app.
 */
class SupportSessionService implements SupportSessions
{
    /** The permission an app declares to let its staff act as its customers' users. */
    public const PERMISSION = 'support:impersonate';

    /** The ceiling no configuration can raise: one hour. */
    public const MAX_TTL_SECONDS = 3600;

    /** The floor, so a session is long enough to complete a sign-in in. */
    public const MIN_TTL_SECONDS = 60;

    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly Memberships $memberships,
        private readonly Organizations $organizations,
        private readonly StaffAccess $staff,
        private readonly AuthorizationCodes $codes,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function begin(NewSupportSession $request, ?SupportCodeRequest $code = null): StartedSupportSession
    {
        $reason = trim($request->reason);

        if ($reason === '') {
            throw SupportSessionRefused::because(SupportSessionRefusal::ReasonRequired);
        }

        // Acting as yourself is not support, and a row saying it was would launder an
        // ordinary sign-in into one with no refresh token and a misleading audit trail.
        if ($request->actorId === $request->targetUserId) {
            throw SupportSessionRefused::because(SupportSessionRefusal::SelfImpersonation);
        }

        $client = $this->eligibleClient($request->clientId);

        // A code must be redeemable somewhere. The redirect URI a code is bound to is
        // checked against the registered set every time one is minted (issueCode()); here
        // the question is only whether this app can complete a sign-in at all.
        if ($client->redirect_uris === []) {
            throw SupportSessionRefused::because(SupportSessionRefusal::NoRedirectUri);
        }

        $organization = $this->organizations->find($request->organizationId);

        if ($organization === null || $organization->status !== OrganizationStatus::Active) {
            throw SupportSessionRefused::because(SupportSessionRefusal::OrganizationInactive);
        }

        // An ACTIVE member. An invited person has not accepted anything yet, and a
        // suspended one has been deliberately kept out; acting as either would put
        // somebody into the organization that its own administrators did not.
        $membership = $this->memberships->of($request->organizationId, $request->targetUserId);

        if ($membership === null || $membership->status !== MembershipStatus::Active) {
            throw SupportSessionRefused::because(SupportSessionRefusal::TargetNotMember);
        }

        $this->authorizeActor($request, $client);

        // One transaction for the session, its announcement and its first code: a code
        // request that fails (an unregistered redirect URI, a malformed PKCE challenge)
        // leaves no session behind that the customer was told about and nobody used.
        return DB::transaction(function () use ($request, $client, $reason, $code): StartedSupportSession {
            $session = SupportSession::query()->create([
                'actor_id' => $request->actorId,
                'actor_kind' => $request->actorKind,
                'target_user_id' => $request->targetUserId,
                'organization_id' => $request->organizationId,
                'client_id' => $client->client_id,
                'scopes' => $this->scopesFor($client, $request->scopes),
                'reason' => $reason,
                'expires_at' => now()->addSeconds($this->ttl($request->ttlSeconds)),
            ]);

            $minted = $code === null ? null : $this->mint($session, $client, $code);

            $this->announce($session);

            return new StartedSupportSession($session, $minted);
        });
    }

    public function issueCode(string $sessionId, string $actorId, SupportCodeRequest $code): string
    {
        // Bound into the query: an ended or expired session, and somebody else's, are the
        // same "no" — the actor is part of what identifies the session, not a field
        // checked on it afterwards.
        $session = SupportSession::query()
            ->whereKey($sessionId)
            ->where('actor_id', $actorId)
            ->active()
            ->first();

        if ($session === null) {
            throw SupportSessionRefused::because(SupportSessionRefusal::SessionNotActive);
        }

        return $this->mint($session, $this->eligibleClient($session->client_id), $code);
    }

    public function active(string $sessionId): ?SupportSession
    {
        return SupportSession::query()->whereKey($sessionId)->active()->first();
    }

    public function openFor(string $actorId): array
    {
        return array_values(SupportSession::query()
            ->where('actor_id', $actorId)
            ->active()
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->get()
            ->all());
    }

    public function end(string $sessionId, ?string $endedBy = null): void
    {
        DB::transaction(function () use ($sessionId, $endedBy): void {
            $session = SupportSession::query()->whereKey($sessionId)->whereNull('ended_at')->lockForUpdate()->first();

            if ($session === null) {
                return;
            }

            $session->forceFill(['ended_at' => now(), 'ended_by' => $endedBy])->save();

            // Outstanding codes die with the session. The token endpoint re-reads the
            // session and would refuse them anyway; consuming them too means neither check
            // is the only one.
            AuthorizationCode::query()
                ->where('support_session_id', $session->id)
                ->whereNull('consumed_at')
                ->update(['consumed_at' => now()]);

            $revoked = AccessToken::query()
                ->where('support_session_id', $session->id)
                ->whereNull('revoked_at')
                ->update(['revoked_at' => now()]);

            $this->recordOnBothTrails($session, 'support_session.ended', [
                'ended_by' => $endedBy,
                'tokens_revoked' => $revoked,
            ]);
        });
    }

    /**
     * A client support sessions may mint tokens for: one the ENVIRONMENT owns
     * (`organization_id` null), flagged first-party, that uses the authorization-code
     * grant.
     *
     * The consent decision lives here. The person being acted as never agrees to a
     * support session, so its tokens may only go to an app whose ordinary sign-in skips
     * consent anyway — a first-party app of the environment itself. A third-party app, or
     * one a customer registered, would be handed a person's data on somebody else's say-
     * so; that is a consent bypass, and it is refused rather than papered over with a
     * consent screen the person is not there to see.
     */
    private function eligibleClient(string $clientId): Client
    {
        $client = $this->clients->byClientId($clientId);

        if ($client === null) {
            throw SupportSessionRefused::because(SupportSessionRefusal::UnknownClient);
        }

        if (! $client->first_party
            || $client->organization_id !== null
            || ! GrantPolicy::allows($client, 'authorization_code')) {
            throw SupportSessionRefused::because(SupportSessionRefusal::ClientNotEligible);
        }

        return $client;
    }

    /**
     * Staff must hold the app's own `support:impersonate` environment-wide. An environment
     * administrator is authorized by the caller, which is the only party that can know.
     */
    private function authorizeActor(NewSupportSession $request, Client $client): void
    {
        if ($request->actorKind === SupportActorKind::EnvironmentAdmin) {
            return;
        }

        if (! $this->staff->holdsEverywhere($request->actorId, self::PERMISSION, $client->client_id)) {
            throw SupportSessionRefused::because(SupportSessionRefusal::NotPermitted);
        }
    }

    private function mint(SupportSession $session, Client $client, SupportCodeRequest $code): string
    {
        // Exact match against the registered set, the rule every authorization request
        // follows: a code delivered anywhere else is a code handed to whoever controls
        // that address.
        if (! in_array($code->redirectUri, $client->redirect_uris, true)) {
            throw SupportSessionRefused::because(SupportSessionRefusal::RedirectUriNotRegistered);
        }

        return $this->codes->issue(
            clientId: $session->client_id,
            userId: $session->target_user_id,
            organizationId: $session->organization_id,
            redirectUri: $code->redirectUri,
            scopes: array_values($session->scopes),
            codeChallenge: $code->codeChallenge,
            nonce: $code->nonce,
            // No auth_time and no amr: nobody authenticated as the target. The actor's own
            // sign-in is not the target's, and an ID Token asserting one — or an `acr`
            // derived from it — would tell the app a login happened that did not.
            actor: new ActingParty($session->actor_id, $session->id),
        );
    }

    /**
     * What the session's codes carry: the request narrowed to what the client is
     * registered for (or the client's whole set when nothing was asked), and NEVER
     * `offline_access` — an acted grant gets no refresh token, and a scope promising one
     * would be a lie the token endpoint then has to contradict.
     *
     * @param  list<string>  $requested
     * @return list<string>
     */
    private function scopesFor(Client $client, array $requested): array
    {
        $scopes = $requested === []
            ? array_values($client->scopes)
            : array_values(array_filter($requested, fn (string $scope): bool => $client->allows($scope)));

        return array_values(array_unique(array_filter($scopes, fn (string $scope): bool => $scope !== 'offline_access')));
    }

    /**
     * The session's lifetime: what was asked for, within [1 minute, the configured
     * maximum], where the configured maximum can only ever LOWER the one-hour ceiling.
     */
    private function ttl(?int $requested): int
    {
        $configured = config('cbox-id.oauth.support_sessions.max_ttl', self::MAX_TTL_SECONDS);
        $max = is_numeric($configured) ? (int) $configured : self::MAX_TTL_SECONDS;
        $max = max(self::MIN_TTL_SECONDS, min(self::MAX_TTL_SECONDS, $max));

        return max(self::MIN_TTL_SECONDS, min($max, $requested ?? $max));
    }

    /**
     * Audit on both sides, and tell the customer.
     *
     * Both trails because the two readers are different people: the customer's trail is
     * where THEY see who acted as their member and why; the environment's is where the
     * vendor sees what its staff did. The event is scoped to the organization, so the
     * customer's own webhooks receive it — the reason included, because the reason is
     * the only account of it they get.
     */
    private function announce(SupportSession $session): void
    {
        $context = [
            'support_session_id' => $session->id,
            'actor_id' => $session->actor_id,
            'actor_kind' => $session->actor_kind->value,
            'user_id' => $session->target_user_id,
            'client_id' => $session->client_id,
            'reason' => $session->reason,
            'expires_at' => $session->expires_at->toIso8601String(),
        ];

        $this->events->emit(new DomainEvent('support_session.started', $context, $session->organization_id));

        $this->recordOnBothTrails($session, 'support_session.started', $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function recordOnBothTrails(SupportSession $session, string $action, array $context): void
    {
        foreach ([$session->organization_id, null] as $organizationId) {
            $this->audit->record(new AuditEvent(
                action: $action,
                actorType: ActorType::User,
                actorId: $session->actor_id,
                organizationId: $organizationId,
                targetType: 'user',
                targetId: $session->target_user_id,
                context: ['support_session_id' => $session->id, 'organization_id' => $session->organization_id] + $context,
            ));
        }
    }
}
