<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Enums\SupportActorKind;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Exceptions\SupportSessionRefused;
use Cbox\Id\OAuthServer\Models\SupportSession;
use Cbox\Id\OAuthServer\ValueObjects\NewSupportSession;
use Cbox\Id\OAuthServer\ValueObjects\StartedSupportSession;
use Cbox\Id\OAuthServer\ValueObjects\SupportCodeRequest;

/**
 * Support access: an app vendor's staff, or an environment administrator, signing in to
 * ONE app AS one of its customer's users — to see what they see — for a stated reason and
 * at most an hour.
 *
 * The app completes an ordinary authorization-code exchange. What it gets back differs in
 * three ways, all enforced at the token endpoint: every token carries the RFC 8693 `act`
 * claim naming the real actor (`{"sub": "<actor>"}`), there is never a refresh token, and
 * nothing lives past the session. An app that wants to show a "you are acting as…" banner,
 * or refuse a dangerous action while acted, reads `act`.
 *
 * WHO MAY: a {@see SupportActorKind::Staff} actor must hold the app's own
 * `support:impersonate` permission through an ENVIRONMENT-WIDE grant — a grant inside one
 * customer is that customer's support, not the vendor's. A
 * {@see SupportActorKind::EnvironmentAdmin} actor is authorized by the caller.
 *
 * WHICH APPS: only first-party applications the environment itself owns. The person being
 * acted as never consents to a support session, so it may only mint tokens for an app
 * whose ordinary sign-in skips consent anyway — never for a third-party app or one a
 * customer registered, which would hand that app the person's data on someone else's
 * say-so.
 *
 * Both sides are audited — the customer's trail names who acted as their member and why,
 * the environment's trail names what the actor did — and `support_session.started` is
 * emitted for the customer's webhooks.
 */
interface SupportSessions
{
    /**
     * Start a session. With a `$code` request, also mint its first authorization code.
     *
     * @throws SupportSessionRefused naming which check failed
     * @throws InvalidAudience when the session's scopes cannot be audienced to one API; nothing is started
     */
    public function begin(NewSupportSession $request, ?SupportCodeRequest $code = null): StartedSupportSession;

    /**
     * Mint another single-use authorization code for an ACTIVE session — for example when
     * the app starts a fresh authorization request while the session is still open. Only
     * the session's own actor may; the redirect URI must be registered for the session's
     * app. Returns the raw code.
     *
     * @throws SupportSessionRefused
     */
    public function issueCode(string $sessionId, string $actorId, SupportCodeRequest $code): string;

    /** The session, if it exists in this environment and has neither ended nor expired. */
    public function active(string $sessionId): ?SupportSession;

    /**
     * The sessions this actor has open right now, newest first.
     *
     * @return list<SupportSession>
     */
    public function openFor(string $actorId): array;

    /**
     * End a session now: no further codes, outstanding codes die, and every access token
     * it minted is revoked (introspection reports it inactive; a resource server that
     * validates offline stops accepting it at its `exp`, which never passes the session's
     * end). Idempotent — ending an ended session changes nothing.
     */
    public function end(string $sessionId, ?string $endedBy = null): void;
}
