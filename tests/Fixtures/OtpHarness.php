<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Otp\Testing\InteractsWithOtp;

/**
 * Composition site so the shippable InteractsWithOtp trait is type-checked.
 */
class OtpHarness
{
    use InteractsWithOtp;
}
