<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\OAuthServer\Testing\InteractsWithOAuth;

/**
 * Composition site so the shippable InteractsWithOAuth trait is type-checked.
 */
final class OAuthHarness
{
    use InteractsWithOAuth;
}
