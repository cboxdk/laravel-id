<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use RuntimeException;

/**
 * Thrown when a SCIM `sortBy` names an attribute the directory cannot order by — one it
 * does not store, or a multi-valued one with no single value per resource.
 *
 * RFC 7644 §3.4.2.3 says the server SHALL order by the attribute, and is silent on an
 * attribute it cannot. Ordering by something else and answering 200 would hand a client
 * that pages through "sorted" results a different order than it asked for, with no way
 * to tell; the SCIM layer answers `400 invalidValue` instead.
 */
class UnsupportedDirectorySort extends RuntimeException
{
    public static function attribute(string $attribute): self
    {
        return new self("The attribute [{$attribute}] cannot be sorted on.");
    }

    public static function notSupported(): self
    {
        return new self('This directory store does not support sorting.');
    }
}
