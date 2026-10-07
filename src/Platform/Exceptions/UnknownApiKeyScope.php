<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use Cbox\Id\Platform\Contracts\ManagementScopes;
use InvalidArgumentException;

/**
 * A management key was asked to carry a scope nothing recognises.
 *
 * Refused rather than stored: an unknown string on a key grants nothing today, and grants
 * whatever an endpoint added tomorrow happens to call it. {@see ManagementScopes}
 */
class UnknownApiKeyScope extends InvalidArgumentException
{
    /**
     * @param  list<string>  $scopes
     */
    public static function for(array $scopes): self
    {
        return new self('Unknown management key scope: '.implode(', ', $scopes).'.');
    }
}
