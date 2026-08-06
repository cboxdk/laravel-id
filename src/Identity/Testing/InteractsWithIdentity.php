<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Testing;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\Subject;
use Illuminate\Support\Str;

/**
 * Convenience for creating subjects in tests:
 *
 *     $subject = $this->makeUser('alice@example.com', password: 'secret');
 */
trait InteractsWithIdentity
{
    protected function makeUser(?string $email = null, ?string $name = null, ?string $password = null): Subject
    {
        return app(Subjects::class)->create(
            $email ?? Str::lower(Str::random(8)).'@example.test',
            $name,
            $password,
        );
    }
}
