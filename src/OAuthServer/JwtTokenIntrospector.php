<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Closure;
use Throwable;

class JwtTokenIntrospector implements TokenIntrospector
{
    public function __construct(
        private readonly TokenSigner $signer,
        /**
         * Resolved lazily, never captured.
         *
         * This is a singleton and `Subjects` is environment-scoped; a captured instance
         * would answer for the first environment the process saw, which on a queue worker
         * is whichever job ran first. The same reasoning as {@see DatabaseKeyManager}'s
         * environment id.
         */
        private readonly ?Closure $subjects = null,
    ) {}

    public function introspect(string $token): Introspection
    {
        try {
            // Accept every alg the metadata advertises for signing (RS256/ES256/EdDSA),
            // so an EdDSA-signed token isn't silently un-introspectable/un-exchangeable.
            $claims = $this->signer->verify($token, [SigningAlg::RS256, SigningAlg::ES256, SigningAlg::EdDSA]);
        } catch (Throwable) {
            return Introspection::inactive();
        }

        $jti = $claims->string('jti');

        if ($jti === null) {
            return Introspection::inactive();
        }

        $record = AccessToken::query()->where('jti', $jti)->first();

        if ($record === null || $record->revoked_at !== null || $record->expires_at->isPast()) {
            return Introspection::inactive();
        }

        // AND THE PERSON HAS TO STILL BE ONE. A signed, unexpired, unrevoked token said
        // nothing about whether its subject still has an account — `UserStatus` appeared
        // nowhere in this module. Deactivation revoked refresh tokens, so the renewal
        // stopped; every access token already minted stayed good until it expired, and
        // RFC 8693 token exchange took one of those and minted a fresh one, which meant
        // "until it expires" renewed itself for as long as the holder kept asking. A
        // leaver's connected application never lost access.
        //
        // Asked HERE because introspection is the one question every consumer already
        // asks: UserInfo, the decisions endpoint, /frontend/v1/session, the introspection
        // endpoint and token exchange all route through it, and a check at each of them
        // is five checks that can drift. Client-credentials tokens have no subject and
        // skip it — there is no person to have been deactivated.
        $subject = $claims->subject();

        if ($subject !== null && $this->subjectIsSuspended($subject)) {
            return Introspection::inactive();
        }

        $scope = $claims->string('scope') ?? '';
        $scopes = $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));

        return Introspection::active($claims->subject(), $claims->string('client_id'), $scopes, $claims->all());
    }

    /**
     * Whether this token's subject is a known account that is no longer Active.
     *
     * DELIBERATELY NOT `isActive()`, which answers false for two different facts: "this
     * account is disabled" and "there is no such account". Only the first is a reason to
     * refuse a token. Subjects are never hard-deleted here — {@see UserStatus} has
     * Active, Disabled and Locked and no fourth state — so a `sub` with no row is a token
     * minted for an id this platform never had an account for, which the signature
     * already vouches for and which nothing in production produces.
     *
     * Locked counts alongside Disabled: an account locked out after failed attempts or
     * an administrator's intervention should not go on being represented by a token
     * issued before the lock.
     *
     * A null resolver means TRUE (not suspended), narrowly and on purpose: this class is
     * constructible without one, and a missing wire must not silently invalidate every
     * user token on the platform. The container always supplies it — see
     * OAuthServerServiceProvider.
     */
    private function subjectIsSuspended(string $subjectId): bool
    {
        if ($this->subjects === null) {
            return false;
        }

        /** @var Subjects $subjects */
        $subjects = ($this->subjects)();
        $subject = $subjects->find($subjectId);

        return $subject !== null && $subject->status !== UserStatus::Active;
    }

    public function revoke(string $jti): void
    {
        AccessToken::query()
            ->where('jti', $jti)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }
}
