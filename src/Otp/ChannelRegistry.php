<?php

declare(strict_types=1);

namespace Cbox\Id\Otp;

use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\Contracts\OtpChannels;
use Cbox\Id\Otp\Exceptions\UnknownOtpChannel;
use Illuminate\Contracts\Container\Container;

/**
 * Deny-by-default {@see OtpChannels} registry.
 *
 * Channels are declared as `key => channel-class` (from `cbox-id.otp.channels`)
 * and resolved lazily from the container on first use, or registered as a ready
 * instance at runtime (a host wiring its SMS provider, a test injecting a fake).
 * A key with neither is REFUSED — never a silent no-op.
 */
class ChannelRegistry implements OtpChannels
{
    /**
     * @var array<string, OtpChannel>
     */
    private array $resolved = [];

    /**
     * @var array<string, class-string<OtpChannel>>
     */
    private array $deferred = [];

    /**
     * @param  array<string, class-string<OtpChannel>>  $map
     */
    public function __construct(private readonly Container $container, array $map = [])
    {
        foreach ($map as $key => $class) {
            $this->deferred[$key] = $class;
        }
    }

    public function register(string $key, OtpChannel $channel): void
    {
        $this->resolved[$key] = $channel;
        unset($this->deferred[$key]);
    }

    public function has(string $key): bool
    {
        return isset($this->resolved[$key]) || isset($this->deferred[$key]);
    }

    public function channel(string $key): OtpChannel
    {
        if (isset($this->resolved[$key])) {
            return $this->resolved[$key];
        }

        if (isset($this->deferred[$key])) {
            $channel = $this->container->make($this->deferred[$key]);

            // Deny-by-default even here: a mapped class that does not resolve to an
            // OtpChannel is treated as unregistered, never silently trusted.
            if (! $channel instanceof OtpChannel) {
                throw UnknownOtpChannel::forKey($key);
            }

            // Cache so a channel stays a singleton for the request.
            $this->resolved[$key] = $channel;
            unset($this->deferred[$key]);

            return $channel;
        }

        throw UnknownOtpChannel::forKey($key);
    }

    public function keys(): array
    {
        return array_values(array_unique([
            ...array_keys($this->resolved),
            ...array_keys($this->deferred),
        ]));
    }
}
