<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Testing;

use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Senders\ArraySmsSender;

/**
 * Test ergonomics for anything that sends a text, in the spirit of `Mail::fake()`:
 *
 *     uses(InteractsWithSms::class);
 *
 *     it('texts a code', function () {
 *         $sms = $this->fakeSms();
 *         // … drive the flow …
 *         $sms->assertSent('+4512345678');
 *         $code = $sms->latestCode();
 *     });
 */
trait InteractsWithSms
{
    protected function fakeSms(): ArraySmsSender
    {
        $fake = new ArraySmsSender;

        app()->instance(SmsSender::class, $fake);

        return $fake;
    }
}
