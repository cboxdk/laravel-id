<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\OAuthServer\Contracts\ActionApprovals;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Enums\GrantPollStatus;
use Cbox\Id\OAuthServer\Exceptions\CibaAccessDenied;
use Cbox\Id\OAuthServer\Exceptions\CibaAuthorizationPending;
use Cbox\Id\OAuthServer\Exceptions\CibaExpired;
use Cbox\Id\OAuthServer\Exceptions\CibaRateLimited;
use Cbox\Id\OAuthServer\Exceptions\CibaSlowDown;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Exceptions\ScopeNotGranted;
use Cbox\Id\OAuthServer\Exceptions\UnknownUserHint;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\GrantedScopes;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;
use Cbox\Id\OAuthServer\ValueObjects\BackchannelAuthenticationResult;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;

/**
 * Poll-mode CIBA (OpenID Connect CIBA Core). The polling state machine mirrors the
 * device authorization grant ({@see DeviceAuthorizationService}) — hashed-at-rest
 * single-use secret, TTL, poll-interval `slow_down`, and a locked single-use mint —
 * differing only in that there is no user_code: the user is resolved from
 * `login_hint` up front and approves out-of-band, so the notification/approval
 * surface is the host's (driven by the emitted domain event).
 */
class CibaAuthenticationService implements BackchannelAuthentication
{
    private const DEFAULT_TTL_SECONDS = 300;

    private const DEFAULT_POLL_INTERVAL = 5;

    /** Requests per person, across every client, in the window below — the prompt-fatigue cap. */
    private const DEFAULT_PER_PERSON = 10;

    private const DEFAULT_PER_PERSON_WINDOW = 600;

    public function __construct(
        private readonly Subjects $subjects,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function request(
        Client $client,
        array $scopes,
        string $loginHint,
        ?string $bindingMessage = null,
        ?string $nonce = null,
        ?int $requestedExpiry = null,
        ?string $resource = null,
    ): BackchannelAuthenticationResult {
        // Resolve the user the client is asking to authenticate — by opaque id, or by an
        // email address the person has CONFIRMED. An unconfirmed address proves nothing
        // about who reads it, and a prompt keyed to one could land with whoever typed it
        // into a sign-up form. Deny-by-default: an unresolvable hint never creates a
        // request, and an unconfirmed one reads exactly like an unknown one.
        $subject = $this->subjects->find($loginHint);

        if ($subject === null) {
            $byEmail = $this->subjects->findByEmail($loginHint);
            $subject = $byEmail !== null && $byEmail->emailVerified ? $byEmail : null;
        }

        if ($subject === null) {
            throw new UnknownUserHint;
        }

        // However many clients ask, one person sees at most this many prompts in the
        // window. A person who has dismissed thirty approves the thirty-first; this is the
        // ceiling on how many they can be shown.
        $key = 'cbox-id:ciba:person:'.$subject->id;
        $limit = self::configInt('cbox-id.oauth.ciba.rate_limits.per_person', self::DEFAULT_PER_PERSON);
        $window = self::configInt('cbox-id.oauth.ciba.rate_limits.per_person_window', self::DEFAULT_PER_PERSON_WINDOW);

        if (RateLimiter::tooManyAttempts($key, $limit)) {
            throw new CibaRateLimited(RateLimiter::availableIn($key));
        }

        RateLimiter::hit($key, $window);

        // The same ceiling the device grant applies, for the same reason and with the same
        // refusal: CIBA is machine-initiated, so nobody is stranded by a 400, and a grant
        // that stored unfiltered scopes handed the token endpoint a refresh token the
        // client's registration withheld. See GrantedScopes.
        $granted = GrantedScopes::for($client, $scopes);

        if ($granted !== $scopes && $scopes !== []) {
            throw ScopeNotGranted::forClient($client->client_id, array_values(array_diff($scopes, $granted)));
        }

        $scopes = $granted;

        $authReqId = 'auth_req_'.bin2hex(random_bytes(32));
        $interval = $this->pollInterval();
        $ttl = $this->effectiveTtl($requestedExpiry, $interval);

        $model = BackchannelAuthRequest::query()->create([
            'auth_req_id_hash' => hash('sha256', $authReqId),
            'client_id' => $client->client_id,
            'user_id' => $subject->id,
            'scopes' => $scopes,
            'binding_message' => $bindingMessage,
            'nonce' => $nonce,
            'resource' => $resource,
            'status' => GrantPollStatus::Pending,
            'interval' => $interval,
            'expires_at' => now()->addSeconds($ttl),
        ]);

        // The host listens for this to notify the user's authentication device and
        // drive its approval surface. The payload carries the INTERNAL request id
        // (the approval handle) — never the client's auth_req_id.
        $this->events->emit(new DomainEvent(
            'oauth.backchannel_authentication_requested',
            [
                'request_id' => $model->id,
                'client_id' => $client->client_id,
                'user_id' => $subject->id,
                'binding_message' => $bindingMessage,
                'scopes' => $scopes,
                'resource' => $resource,
            ],
        ));

        $this->audit->record(new AuditEvent(
            action: 'oauth.ciba.requested',
            actorType: ActorType::Service,
            actorId: $client->client_id,
            targetType: 'user',
            targetId: $subject->id,
            context: ['request_id' => $model->id, 'scopes' => $scopes, 'resource' => $resource, 'binding_message' => $bindingMessage],
        ));

        return new BackchannelAuthenticationResult(
            requestId: $model->id,
            authReqId: $authReqId,
            subjectId: $subject->id,
            expiresIn: $ttl,
            interval: $interval,
            bindingMessage: $bindingMessage,
        );
    }

    public function approve(string $requestId, string $subjectId, ?string $organizationId = null): bool
    {
        $approved = $this->transitionPending($requestId, $subjectId, [
            'status' => GrantPollStatus::Approved,
            'organization_id' => $organizationId,
            'approved_at' => now(),
        ]);

        if ($approved) {
            $this->recordDecision('oauth.ciba.approved', $requestId, $subjectId, $organizationId);
        }

        return $approved;
    }

    public function deny(string $requestId, string $subjectId): bool
    {
        $denied = $this->transitionPending($requestId, $subjectId, ['status' => GrantPollStatus::Denied]);

        if ($denied) {
            $this->recordDecision('oauth.ciba.denied', $requestId, $subjectId, null);
        }

        return $denied;
    }

    /** Every decision on a backchannel request, by the person it was for. */
    private function recordDecision(string $action, string $requestId, string $subjectId, ?string $organizationId): void
    {
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::User,
            actorId: $subjectId,
            organizationId: $organizationId,
            targetType: 'ciba_request',
            targetId: $requestId,
        ));
    }

    public function redeem(string $clientId, string $authReqId): AuthorizedGrant
    {
        $record = BackchannelAuthRequest::query()
            ->where('auth_req_id_hash', hash('sha256', $authReqId))
            ->where('client_id', $clientId)
            ->first();

        // An ACTION approval is spent by the host ({@see ActionApprovals::consume()}) and is
        // never a token: it reads as unknown here, whichever client presents it.
        if ($record === null || $record->action_digest !== null) {
            throw new InvalidGrant('unknown auth_req_id');
        }

        if ($record->expires_at->isPast()) {
            throw new CibaExpired;
        }

        // Enforce the polling interval: too-fast polling gets slow_down without
        // advancing the clock. The last_polled_at write for the pending path is
        // committed OUTSIDE the mint transaction below, so a rolled-back mint can
        // never let the client poll unthrottled.
        if ($record->last_polled_at !== null
            && $record->last_polled_at->copy()->addSeconds($record->interval)->isFuture()) {
            throw new CibaSlowDown;
        }

        if ($record->status === GrantPollStatus::Denied) {
            throw new CibaAccessDenied;
        }

        // An auth_req_id already exchanged for a token is spent — never mint again.
        if ($record->status === GrantPollStatus::Redeemed) {
            throw new InvalidGrant('auth_req_id already used');
        }

        if ($record->status !== GrantPollStatus::Approved) {
            $record->forceFill(['last_polled_at' => now()])->save();

            throw new CibaAuthorizationPending;
        }

        // Single-use: flip approved -> redeemed under a row lock in a transaction so
        // two concurrent polls can't both observe Approved and each mint a token.
        return DB::transaction(function () use ($record): AuthorizedGrant {
            $locked = BackchannelAuthRequest::query()->whereKey($record->id)->lockForUpdate()->first();

            if ($locked === null || $locked->status !== GrantPollStatus::Approved) {
                throw new InvalidGrant('auth_req_id already used');
            }

            $grant = new AuthorizedGrant(
                userId: (string) $locked->user_id,
                organizationId: $locked->organization_id,
                scopes: array_values($locked->scopes),
                nonce: $locked->nonce,
                authTime: $locked->approved_at?->getTimestamp(),
                resource: $locked->resource,
            );

            $locked->forceFill(['status' => GrantPollStatus::Redeemed, 'last_polled_at' => now()])->save();

            return $grant;
        });
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    private function transitionPending(string $requestId, string $subjectId, array $attributes): bool
    {
        return (bool) BackchannelAuthRequest::query()
            ->whereKey($requestId)
            // The approving subject MUST be the one the request was raised for. CIBA
            // approval IS the consent step for an agent acting on a user's behalf, so
            // without this any user who learns a request id could consent on another
            // user's behalf — and the redeemed token is minted for THAT user. Required
            // rather than optional so no caller can omit it, matching the device flow.
            ->where('user_id', $subjectId)
            ->where('status', GrantPollStatus::Pending)
            ->where('expires_at', '>', now())
            ->update($attributes);
    }

    /**
     * The client may ask for a shorter window (`requested_expiry`); the configured
     * ttl is the ceiling and the default, and the poll interval is the floor.
     */
    private function effectiveTtl(?int $requestedExpiry, int $interval): int
    {
        $ceiling = $this->ttlSeconds();

        if ($requestedExpiry === null) {
            return $ceiling;
        }

        return max($interval, min($requestedExpiry, $ceiling));
    }

    private function ttlSeconds(): int
    {
        $value = config('cbox-id.oauth.ciba.ttl_seconds', self::DEFAULT_TTL_SECONDS);

        return is_numeric($value) ? (int) $value : self::DEFAULT_TTL_SECONDS;
    }

    private function pollInterval(): int
    {
        $value = config('cbox-id.oauth.ciba.poll_interval', self::DEFAULT_POLL_INTERVAL);

        return is_numeric($value) ? (int) $value : self::DEFAULT_POLL_INTERVAL;
    }

    /** A positive whole number from config, or the default when it is not one. */
    private static function configInt(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }
}
