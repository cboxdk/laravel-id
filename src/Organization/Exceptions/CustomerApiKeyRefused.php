<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use Cbox\Id\Organization\Enums\ApiKeyRefusal;
use RuntimeException;

/**
 * A customer API key was not issued. {@see self::$reason} says why, as a type, so a
 * caller (and a test) can tell a permission the holder does not have apart from an app
 * that never enabled keys — both used to be "the same exception class".
 */
class CustomerApiKeyRefused extends RuntimeException
{
    /**
     * @param  list<string>  $permissions  the offending permissions, for {@see ApiKeyRefusal::PermissionNotHeld}
     */
    public function __construct(
        public readonly ApiKeyRefusal $reason,
        string $message,
        public readonly array $permissions = [],
    ) {
        parent::__construct($message);
    }

    public static function because(ApiKeyRefusal $reason, string $message): self
    {
        return new self($reason, $message);
    }

    /**
     * @param  list<string>  $permissions
     */
    public static function permissionsNotHeld(array $permissions, string $clientId): self
    {
        return new self(
            ApiKeyRefusal::PermissionNotHeld,
            sprintf(
                'The holder does not currently hold [%s] for app [%s]; a key can only carry permissions its holder has.',
                implode(', ', $permissions),
                $clientId,
            ),
            $permissions,
        );
    }
}
