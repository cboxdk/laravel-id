<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Identity\Models\User;

/**
 * A consumer-style subclass, used to prove the package resolves the configured
 * user model instead of its own.
 */
final class CustomUser extends User
{
    public function isCustom(): bool
    {
        return true;
    }
}
