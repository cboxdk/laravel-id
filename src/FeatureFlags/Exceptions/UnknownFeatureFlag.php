<?php

declare(strict_types=1);

namespace Cbox\Id\FeatureFlags\Exceptions;

use RuntimeException;

/**
 * No flag with that id in this environment. Also the answer for a flag that exists in
 * ANOTHER environment: the two are indistinguishable by design.
 */
class UnknownFeatureFlag extends RuntimeException
{
    public static function forId(string $flagId): self
    {
        return new self(sprintf('No feature flag [%s] in this environment.', $flagId));
    }
}
