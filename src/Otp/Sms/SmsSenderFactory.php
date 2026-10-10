<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms;

use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\Senders\ArraySmsSender;
use Cbox\Id\Otp\Sms\Senders\BirdSmsSender;
use Cbox\Id\Otp\Sms\Senders\FortySixElksSmsSender;
use Cbox\Id\Otp\Sms\Senders\LogSmsSender;
use Cbox\Id\Otp\Sms\Senders\MessageBirdSmsSender;
use Cbox\Id\Otp\Sms\Senders\TwilioSmsSender;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\Factory;
use Psr\Log\LoggerInterface;

/**
 * Builds the {@see SmsSender} named by `cbox-id.sms.driver` from its block under
 * `cbox-id.sms.drivers`. A driver name that is not one of the shipped ones may be a
 * class implementing {@see SmsSender} (a host's own gateway), resolved from the
 * container; anything else is refused.
 *
 * Credentials are read when the sender is BUILT, which is when the first text is sent —
 * not at boot — so a deployment that never turns SMS on never needs them, and one that
 * forgot one learns at the first send, with the setting named.
 */
class SmsSenderFactory
{
    public function __construct(private readonly Application $app) {}

    public function make(string $driver): SmsSender
    {
        $config = config('cbox-id.sms.drivers.'.$driver);
        $config = is_array($config) ? $config : [];
        $timeout = config('cbox-id.sms.timeout_seconds', 10);
        $timeout = is_numeric($timeout) ? max(1, (int) $timeout) : 10;

        /** @var array<string, mixed> $config */
        return match ($driver) {
            'log' => new LogSmsSender($this->app->make(LoggerInterface::class), $this->app->environment('production')),
            'array' => new ArraySmsSender,
            'twilio' => new TwilioSmsSender($this->app->make(Factory::class), $config, $timeout),
            'messagebird' => new MessageBirdSmsSender($this->app->make(Factory::class), $config, $timeout),
            'bird' => new BirdSmsSender($this->app->make(Factory::class), $config, $timeout),
            '46elks' => new FortySixElksSmsSender($this->app->make(Factory::class), $config, $timeout),
            default => $this->custom($driver),
        };
    }

    private function custom(string $driver): SmsSender
    {
        if (class_exists($driver) && is_a($driver, SmsSender::class, true)) {
            $sender = $this->app->make($driver);

            if ($sender instanceof SmsSender) {
                return $sender;
            }
        }

        throw SmsDeliveryFailed::unknownDriver($driver);
    }
}
