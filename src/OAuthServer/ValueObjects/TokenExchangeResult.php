<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * The outcome of an RFC 8693 token exchange: the issued token plus the scopes it was
 * actually granted. The endpoint echoes the scope (RFC 8693 §2.2.1 requires it when
 * the issued scope differs from what was requested — e.g. an empty request that
 * inherited the subject token's scopes).
 */
readonly class TokenExchangeResult
{
    /**
     * @param  list<string>  $scopes
     */
    public function __construct(
        public IssuedToken $token,
        public array $scopes,
    ) {}
}
