<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use InvalidArgumentException;

/**
 * The credentials offered for an HR system are missing something the connector needs, or
 * hold a value it will not use (a Workday address that is not Workday's).
 *
 * Carries the offending keys — never the values — so a form can mark the field.
 */
class IncompleteHrisCredentials extends InvalidArgumentException
{
    /**
     * @param  list<string>  $keys
     */
    public function __construct(string $message, public readonly array $keys = [])
    {
        parent::__construct($message);
    }

    /**
     * @param  list<string>  $keys
     */
    public static function missing(string $provider, array $keys): self
    {
        return new self("{$provider} needs: ".implode(', ', $keys).'.', $keys);
    }

    public static function invalid(string $provider, string $key, string $why): self
    {
        return new self("{$provider}: {$why}", [$key]);
    }
}
