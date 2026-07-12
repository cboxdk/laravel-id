<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Testing;

use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Identity\Models\User;
use Illuminate\Support\Str;

/**
 * Convenience for creating users in tests:
 *
 *     $user = $this->makeUser('alice@example.com', password: 'secret');
 */
trait InteractsWithIdentity
{
    protected function makeUser(?string $email = null, ?string $name = null, ?string $password = null): User
    {
        return app(UserDirectory::class)->create(
            $email ?? Str::lower(Str::random(8)).'@example.test',
            $name,
            $password,
        );
    }
}
