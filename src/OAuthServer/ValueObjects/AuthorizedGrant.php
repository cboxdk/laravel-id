<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The trusted result of exchanging a valid authorization code (PKCE verified).
 */
readonly class AuthorizedGrant
{
    /**
     * @param  list<string>  $scopes
     * @param  list<string>  $amr  authentication methods used at login (OIDC amr)
     */
    public function __construct(
        public string $userId,
        public ?string $organizationId,
        public array $scopes,
        public ?string $nonce = null,
        public ?int $authTime = null,
        public array $amr = [],

        /**
         * The resource indicator this authorization was granted for, if any.
         *
         * Carried out of the exchange so the token endpoint can refuse a redemption that
         * asks for a different audience than the one the user agreed to.
         */
        public ?string $resource = null,

        /**
         * The sign-in session the person approved from, when the host said which — the
         * source of the ID Token's `sid` (OIDC Back-Channel Logout 1.0 §2.1).
         */
        public ?string $sessionId = null,

        /**
         * Who is really acting, when this grant came from a support session's code. The
         * token endpoint mints such a grant with `act`, no refresh token and the
         * session's lifetime cap — and only after re-reading the session.
         */
        public ?ActingParty $actor = null,
    ) {}
}
