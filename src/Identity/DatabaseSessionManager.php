<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\ActionDenied;
use Cbox\Id\ExternalActions\Payloads\LoginPayload;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\LogoutPropagator;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;

/**
 * The default {@see SessionManager}: sessions are rows, ended by revocation, by their
 * absolute lifetime, or by sitting idle.
 *
 * HOW LONG A SESSION LASTS is two levels. The constructor's `$ttlMinutes` and
 * `$idleMinutes` are the DEPLOYMENT's (`cbox-id.sessions.*`) and are the ceiling; the
 * current environment's authentication policy may shorten either for its own people
 * ({@see AuthPolicy::$sessionAbsoluteMinutes}, {@see AuthPolicy::$sessionIdleMinutes}),
 * never lengthen them. Both are read when a session is started AND when it is checked, so
 * an environment that shortens its sessions ends the long ones already running at their
 * new length rather than letting them run out the old one.
 */
class DatabaseSessionManager implements SessionManager
{
    private const DEFAULT_TTL_MINUTES = 60 * 24;

    /** Only rewrite last_active_at once per this many seconds (write-amortization). */
    private const TOUCH_THROTTLE_SECONDS = 60;

    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly ActionPipeline $actions,
        private readonly int $ttlMinutes = self::DEFAULT_TTL_MINUTES,
        // Idle (inactivity) timeout in minutes; 0 disables it and only the
        // absolute ttl applies.
        private readonly int $idleMinutes = 0,
    ) {}

    /**
     * @throws ActionDenied when a {@see HookPoint::PostLogin} hook vetoes the login
     */
    public function start(
        string $userId,
        ?string $organizationId,
        array $amr,
        ?string $ip = null,
        ?string $userAgent = null,
    ): Session {
        // Inline hook: the host's last word on a login the platform has already
        // accepted. It runs HERE, on the one primitive every login path funnels
        // through — password, magic link, SSO, CIBA, and whatever a host builds on the
        // contracts — because a gate bolted onto individual login services is a gate
        // the next login service forgets.
        //
        // Before the row is written, so a veto leaves no session behind, and no
        // enrichment is consumed: this point decides, it does not decorate. Claims are
        // assembled at token_minting, which is the point that owns them.
        //
        // FAIL POLICY — fail-OPEN by default, and this is the one hook point where
        // that is the right default. This is the hottest path in the product; failing
        // closed hands every tenant a single customer-controlled URL whose outage
        // locks all of their users out of everything, the admin console included. The
        // tradeoff is genuinely the host's, so `fail_policy.post_login => 'closed'`
        // buys the stricter reading. An explicit deny always blocks, either way.
        $outcome = $this->actions->run(HookPoint::PostLogin, ActionContext::for(new LoginPayload(
            userId: $userId,
            organizationId: $organizationId,
            amr: $amr,
            ip: $ip,
            userAgent: $userAgent,
        )));

        if (! $outcome->allowed) {
            throw ActionDenied::because($outcome->reason);
        }

        $session = new Session;
        $session->fill([
            'user_id' => $userId,
            'organization_id' => $organizationId,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'amr' => $amr,
            'last_active_at' => now(),
            'expires_at' => now()->addMinutes($this->absoluteMinutes()),
        ]);
        $session->save();

        $this->events->emit(new DomainEvent('user.session_started', ['user_id' => $userId], $organizationId));
        $this->audit->record(new AuditEvent(
            action: 'user.session_started',
            actorType: ActorType::User,
            actorId: $userId,
            organizationId: $organizationId,
            targetType: 'session',
            targetId: $session->id,
            context: ['amr' => $amr],
        ));

        return $session;
    }

    public function active(string $sessionId): ?Session
    {
        $session = Session::query()->whereKey($sessionId)->first();

        if ($session === null || $session->revoked_at !== null || $session->expires_at->isPast()) {
            return null;
        }

        // The absolute lifetime as it is NOW: `expires_at` was written with the length in
        // force when the session started, and an environment that has since shortened it
        // means the shorter one for sessions already running too. Only asked where the
        // environment chose a length — otherwise `expires_at` is already the answer.
        if ($session->created_at !== null
            && $this->environmentPolicy()?->sessionAbsoluteMinutes !== null
            && $session->created_at->copy()->addMinutes($this->absoluteMinutes())->isPast()) {
            return null;
        }

        // Idle timeout: a session untouched for longer than the idle window is
        // treated as expired, independent of the absolute ttl.
        $idle = $this->idleMinutes();

        if ($idle > 0 && $session->last_active_at !== null
            && $session->last_active_at->copy()->addMinutes($idle)->isPast()) {
            return null;
        }

        $this->touch($session);

        return $session;
    }

    /**
     * The absolute lifetime in force: the environment's choice, bounded by the deployment's.
     */
    private function absoluteMinutes(): int
    {
        $chosen = $this->environmentPolicy()?->sessionAbsoluteMinutes;

        return $chosen === null || $chosen < 1 ? $this->ttlMinutes : min($chosen, $this->ttlMinutes);
    }

    /**
     * The idle timeout in force, 0 for none: the environment's choice, bounded by the
     * deployment's — or, where the deployment sets no idle timeout, by the absolute lifetime,
     * past which an idle window could never fire anyway.
     */
    private function idleMinutes(): int
    {
        $chosen = $this->environmentPolicy()?->sessionIdleMinutes;

        if ($chosen === null || $chosen < 1) {
            return $this->idleMinutes;
        }

        return min($chosen, $this->idleMinutes > 0 ? $this->idleMinutes : $this->absoluteMinutes());
    }

    /**
     * The current environment's policy, or null where none can be read.
     *
     * Resolved per call, not injected: a host may decorate {@see AuthPolicies} with something
     * that revokes sessions — and therefore needs this class — so a constructor dependency
     * would be a cycle. Memoised per request by the policy store itself.
     */
    private function environmentPolicy(): ?AuthPolicy
    {
        return app()->bound(AuthPolicies::class) ? app(AuthPolicies::class)->forEnvironment() : null;
    }

    /**
     * Slide the idle window forward, but write at most once per throttle interval
     * so an active session doesn't cause a DB write on every request.
     */
    private function touch(Session $session): void
    {
        $lastActive = $session->last_active_at;

        if ($lastActive !== null && $lastActive->copy()->addSeconds(self::TOUCH_THROTTLE_SECONDS)->isFuture()) {
            return;
        }

        $session->forceFill(['last_active_at' => now()])->save();
    }

    public function revoke(string $sessionId): void
    {
        $session = Session::query()->whereKey($sessionId)->first();

        if ($session === null || $session->revoked_at !== null) {
            return;
        }

        $session->forceFill(['revoked_at' => now()])->save();

        $this->events->emit(new DomainEvent('user.session_revoked', ['user_id' => $session->user_id], $session->organization_id));
        $this->audit->record(new AuditEvent(
            action: 'user.session_revoked',
            actorType: ActorType::System,
            organizationId: $session->organization_id,
            targetType: 'session',
            targetId: $session->id,
        ));

        $this->propagate()->sessionEnded($session->id);
    }

    public function revokeAllForUser(string $userId): void
    {
        Session::query()
            ->where('user_id', $userId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);

        $this->events->emit(new DomainEvent('user.sessions_revoked', ['user_id' => $userId]));
        $this->audit->record(new AuditEvent(
            action: 'user.sessions_revoked',
            actorType: ActorType::System,
            targetType: 'user',
            targetId: $userId,
        ));

        $this->propagate()->subjectSignedOut($userId);
    }

    /**
     * Tell the applications the ended session(s) signed the person in to.
     *
     * HERE, on the primitive, rather than at each caller — for the same reason the
     * post-login hook sits in {@see start()}. Sign-out, "sign out everywhere", an
     * administrator revoking a session, a password reset and a deprovisioned account all
     * end sessions through this class, and a caller that has to remember to notify the
     * relying parties is a caller that one day does not: the person believes they have
     * left, and every application they used keeps them signed in until its own session
     * expires.
     *
     * Resolved per call rather than injected: OAuthServer supplies the binding and
     * registers after Identity, and the implementation only queues work — see the
     * contract — so a relying party that is down cannot slow a sign-out.
     */
    private function propagate(): LogoutPropagator
    {
        return app(LogoutPropagator::class);
    }
}
