<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Exceptions;

use RuntimeException;

/**
 * An origin that could never match anything a browser sends.
 *
 * Thrown rather than skipped: an allow-list that quietly drops the entry a person typed
 * leaves them holding a key that does not work, with no reason why.
 */
final class UnusableOrigin extends RuntimeException
{
    public static function for(string $input): self
    {
        return new self(sprintf(
            '[%s] is not a usable origin. Give a scheme and a host with no path — for example https://app.acme.com, or http://localhost:3000 in development.',
            $input,
        ));
    }

    public static function insecure(string $origin): self
    {
        return new self(sprintf(
            '[%s] uses http, so the key and everything the page does with it would cross the network in the clear. Use https, or a loopback host such as http://localhost:3000 while developing.',
            $origin,
        ));
    }
}
