<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Support;

use Cbox\Id\Federation\ValueObjects\FederationFlowState;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;

/**
 * The `state` and `nonce` of an in-flight federated login, kept somewhere the callback
 * can still read them.
 *
 * The session alone cannot do this job. A provider that answers with `response_mode=
 * form_post` — Apple always, once any scope beyond `openid` is asked for — sends the
 * browser a cross-site POST, and a `SameSite=Lax` session cookie is not sent on one.
 * The callback therefore arrives with a brand-new empty session, finds no stashed state,
 * and tells the person their sign-in link expired. Nothing in the logs looks like a bug:
 * an expired-link message is a real thing that really happens.
 *
 * So the pair is also written to a cookie of its own, `SameSite=None; Secure; HttpOnly`,
 * living ten minutes. That is the ONLY thing about it that differs from the session:
 *
 *  - It is still browser-bound, which is the whole point of `state`. An attacker who
 *    starts their own authorization and injects the resulting code+state into somebody
 *    else's browser is refused, because the victim's browser holds no matching cookie.
 *    Moving the pair to a server-side store keyed by `state` would lose exactly that and
 *    turn a CSRF defence into a lookup table.
 *  - It is scoped to one connection and read once — {@see pull()} forgets it — so a
 *    replayed callback fails closed the same way the session one did.
 *  - `Secure` means it does not exist over plain http. That costs nothing: every provider
 *    that needs `form_post` refuses to register an http redirect URI in the first place,
 *    and the session path still serves ordinary local development.
 *
 * The session write stays. Both are read, session first, so an existing flow in an open
 * browser keeps working across the deploy that adds this.
 */
class FederationFlowStash
{
    /** Ten minutes: an authorization the person has walked away from is not resumable. */
    private const LIFETIME_MINUTES = 10;

    public function put(Request $request, string $connectionId, FederationFlowState $flow): void
    {
        $request->session()->put(self::sessionKey($connectionId), $flow->toArray());

        Cookie::queue(Cookie::make(
            name: self::cookieName($connectionId),
            value: (string) json_encode($flow->toArray()),
            minutes: self::LIFETIME_MINUTES,
            path: '/',
            domain: null,
            secure: true,
            httpOnly: true,
            raw: false,
            sameSite: 'none',
        ));
    }

    /**
     * Read the pair and forget it, wherever it was kept.
     *
     * Both places are cleared even when only one answered: a callback is single-use, and
     * leaving the other copy behind would leave a second chance to replay it.
     */
    public function pull(Request $request, string $connectionId): ?FederationFlowState
    {
        $fromSession = FederationFlowState::fromMixed($request->session()->pull(self::sessionKey($connectionId)));
        $fromCookie = FederationFlowState::fromMixed(self::decode($request->cookie(self::cookieName($connectionId))));

        Cookie::queue(Cookie::forget(self::cookieName($connectionId), '/'));

        return $fromSession ?? $fromCookie;
    }

    private static function sessionKey(string $connectionId): string
    {
        return 'oidc.'.$connectionId;
    }

    /**
     * Named per connection so two sign-ins started in two tabs against two providers do
     * not overwrite one another — the session key has always been per connection, and a
     * shared cookie would have quietly reintroduced the collision.
     */
    private static function cookieName(string $connectionId): string
    {
        return 'cbox_fed_'.preg_replace('/[^A-Za-z0-9]/', '', $connectionId);
    }

    private static function decode(mixed $value): mixed
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        return json_decode($value, true);
    }
}
