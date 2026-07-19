<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A token-exchange (RFC 8693) request that cannot be honoured. Carries the OAuth 2.0
 * error code the token endpoint returns.
 */
final class InvalidTokenExchange extends RuntimeException
{
    public function __construct(public readonly string $error, string $message = '')
    {
        parent::__construct($message);
    }

    public static function inactiveSubject(): self
    {
        return new self('invalid_grant', 'The subject token is not active.');
    }

    public static function unsupportedTokenType(string $type): self
    {
        return new self('invalid_request', "Unsupported subject_token_type [{$type}].");
    }

    public static function scopeExceeded(): self
    {
        return new self('invalid_scope', 'The requested scope exceeds the subject token scope.');
    }
}
