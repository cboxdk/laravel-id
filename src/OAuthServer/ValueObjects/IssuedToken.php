<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

readonly class IssuedToken
{
    /**
     * @param  list<string>  $scopes  the scopes actually GRANTED — the issuer filters the
     *                                request down to what the client is registered for, so this is
     *                                what the `scope` claim carries and what RFC 6749 §5.1 makes
     *                                the token endpoint echo when it differs from the request.
     */
    public function __construct(
        public string $token,
        public string $jti,
        public int $expiresIn,
        // "Bearer", or "DPoP" when sender-constrained to a client key (RFC 9449).
        public string $tokenType = 'Bearer',
        public array $scopes = [],

        /**
         * The audience the token was bound to (a registered API's identifier or an RFC 8707
         * resource), or null for the issuer. A refresh token minted alongside records THIS,
         * not the request, so a refresh can never re-audience what was granted.
         */
        public ?string $audience = null,
    ) {}
}
