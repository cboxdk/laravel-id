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
    ) {}
}
