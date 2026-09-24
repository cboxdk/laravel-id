<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * A `backchannel_logout_uri` resolved somewhere the SSRF guard will not send a request —
 * a private, loopback, link-local or cloud-metadata address.
 */
class UnsafeBackchannelLogoutUri extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self("backchannel_logout_uri refused by the SSRF guard: {$reason}");
    }
}
