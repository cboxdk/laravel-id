<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Otp\Sms\Testing\InteractsWithSms;

/**
 * Composition site so the shippable InteractsWithSms trait is type-checked.
 */
class SmsHarness
{
    use InteractsWithSms;
}
