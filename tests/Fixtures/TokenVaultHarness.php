<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\TokenVault\Testing\InteractsWithTokenVault;

/**
 * Composition site so the shippable InteractsWithTokenVault trait is type-checked.
 */
final class TokenVaultHarness
{
    use InteractsWithTokenVault;
}
