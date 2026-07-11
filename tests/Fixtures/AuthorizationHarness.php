<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Authorization\Testing\InteractsWithAuthorization;

/**
 * Composition site so the shippable InteractsWithAuthorization trait is type-checked.
 */
final class AuthorizationHarness
{
    use InteractsWithAuthorization;
}
