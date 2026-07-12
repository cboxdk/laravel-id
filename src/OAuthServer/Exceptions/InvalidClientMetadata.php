<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A Dynamic Client Registration request carried invalid metadata. The {@see $error}
 * code is one of RFC 7591 §3.2.2's registration error codes — `invalid_redirect_uri`,
 * `invalid_client_metadata`, or `invalid_software_statement` — surfaced verbatim in
 * the 400 response body.
 */
final class InvalidClientMetadata extends RuntimeException
{
    public function __construct(public readonly string $error, string $description)
    {
        parent::__construct($description);
    }

    public static function redirectUri(string $description): self
    {
        return new self('invalid_redirect_uri', $description);
    }

    public static function metadata(string $description): self
    {
        return new self('invalid_client_metadata', $description);
    }
}
