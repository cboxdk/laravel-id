<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Testing;

use Cbox\Id\Platform\Contracts\PlatformOperators;
use Cbox\Id\Platform\Models\PlatformOperator;
use Illuminate\Support\Str;

/**
 * Convenience for provisioning platform operators — the identity above every
 * environment — in tests:
 *
 *     $operator = $this->makeOperator('root@platform.test');
 */
trait InteractsWithPlatform
{
    protected function makeOperator(?string $email = null, ?string $password = null, ?string $name = null): PlatformOperator
    {
        return app(PlatformOperators::class)->create(
            $email ?? Str::lower(Str::random(8)).'@platform.test',
            $password ?? 'a-strong-operator-passphrase',
            $name,
        );
    }
}
