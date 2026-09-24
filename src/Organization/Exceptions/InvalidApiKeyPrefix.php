<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;
use InvalidArgumentException;

/**
 * An app's customer-API-key prefix was refused: malformed, reserved for the platform's
 * own credentials, or already declared by another app in the environment.
 */
class InvalidApiKeyPrefix extends InvalidArgumentException
{
    public static function malformed(string $value): self
    {
        return new self(sprintf(
            'API key prefix [%s] must match %s, e.g. "acme_live".',
            $value,
            ApiKeyPrefix::PATTERN,
        ));
    }

    public static function reserved(string $value): self
    {
        return new self("API key prefix [{$value}] uses a root reserved for the platform's own credentials.");
    }

    public static function taken(string $value): self
    {
        return new self("API key prefix [{$value}] is already declared by another app in this environment.");
    }
}
