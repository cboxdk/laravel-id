<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * A validated RFC 8693 token-exchange request (the token-endpoint parameters for the
 * `urn:ietf:params:oauth:grant-type:token-exchange` grant).
 */
readonly class TokenExchangeRequest
{
    /** RFC 8693 token type URI for an access token. */
    public const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    /**
     * @param  list<string>  $requestedScopes  requested (down-)scope; empty = keep the subject's
     */
    public function __construct(
        public string $subjectToken,
        public string $subjectTokenType,
        public array $requestedScopes = [],
        public ?string $resource = null,
        public ?string $dpopJkt = null,
        public ?string $requestedTokenType = null,

        /**
         * RFC 9396 §6: what the exchanged token is for. Every type must be one the
         * client registered; the token then carries them as `authorization_details`.
         */
        public ?AuthorizationDetails $authorizationDetails = null,
    ) {}
}
