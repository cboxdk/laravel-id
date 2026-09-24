<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A token request whose scopes and `resource` cannot be reconciled with the registered
 * APIs. Carries the OAuth error code the token endpoint returns verbatim: `invalid_target`
 * (RFC 8707 §2) when the audience is missing or ambiguous, `invalid_scope` (RFC 6749 §5.2)
 * when nothing requested may be granted for the audience.
 */
class InvalidAudience extends RuntimeException
{
    public function __construct(public readonly string $error, string $message)
    {
        parent::__construct($message);
    }

    /**
     * @param  list<string>  $identifiers
     */
    public static function ambiguous(array $identifiers): self
    {
        return new self('invalid_target', sprintf(
            'The requested scopes belong to more than one API (%s). Name the one this token is for with the resource parameter.',
            implode(', ', $identifiers),
        ));
    }

    public static function nothingGrantable(): self
    {
        return new self('invalid_scope', 'None of the requested scopes may be granted to this client for the requested audience.');
    }
}
