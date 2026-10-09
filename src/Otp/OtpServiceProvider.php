<?php

declare(strict_types=1);

namespace Cbox\Id\Otp;

use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Crypto\CryptoServiceProvider;
use Cbox\Id\Kernel\Crypto\Exceptions\CryptoConfigurationException;
use Cbox\Id\Otp\Channels\EmailOtpChannel;
use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\Contracts\OtpChannels;
use Cbox\Id\Otp\Contracts\OtpHasher;
use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\Erasure\OtpChallengesErasureStep;
use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Contracts\SmsSendGuard;
use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;
use Cbox\Id\Otp\Sms\RateLimitedSmsSendGuard;
use Cbox\Id\Otp\Sms\SmsDispatcher;
use Cbox\Id\Otp\Sms\SmsMessageComposer;
use Cbox\Id\Otp\Sms\SmsSenderFactory;
use Cbox\Id\Support\PackageConfigMerger;
use Illuminate\Cache\RateLimiter;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Support\ServiceProvider;

class OtpServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // This module's share of a GDPR erasure (see SubjectEraser): the personal data it
        // owns is erased by the module that owns it.
        $this->callAfterResolving(ErasureSteps::class, static function (ErasureSteps $steps, Application $app): void {
            $steps->register($app->make(OtpChallengesErasureStep::class));
        });

        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../../config/cbox-id.php', 'cbox-id');

        // Keyed OTP hasher — derives its HMAC key from the crypto master key so a
        // database dump alone never reveals a code (see KeyedOtpHasher).
        $this->app->singleton(OtpHasher::class, static function (): OtpHasher {
            $configured = config('cbox-id.crypto.key');
            $decoded = is_string($configured) ? self::decodeKey($configured) : false;

            if ($decoded === false) {
                throw CryptoConfigurationException::missingKey();
            }

            return new KeyedOtpHasher($decoded);
        });

        // Deny-by-default channel registry, seeded from `cbox-id.otp.channels`.
        $this->app->singleton(OtpChannels::class, function (Application $app): OtpChannels {
            return new ChannelRegistry($app, $this->channelMap());
        });

        // The framework-mailer email channel, its subject/from taken from config.
        $this->app->bind(EmailOtpChannel::class, static function (Application $app): EmailOtpChannel {
            $subject = config('cbox-id.otp.email.subject');
            $fromAddress = config('cbox-id.otp.email.from.address');
            $fromName = config('cbox-id.otp.email.from.name');

            return new EmailOtpChannel(
                $app->make(Mailer::class),
                is_string($subject) && $subject !== '' ? $subject : 'Your verification code',
                is_string($fromAddress) ? $fromAddress : null,
                is_string($fromName) ? $fromName : null,
            );
        });

        $this->registerSms();

        $this->app->singleton(OtpService::class, function (Application $app): OtpService {
            return new DatabaseOtpService(
                $app->make(OtpChannels::class),
                $app->make(OtpHasher::class),
                $app->make(AuditLog::class),
                $app->make(RateLimiter::class),
                $this->clampedLength(),
                $this->intConfig('cbox-id.otp.ttl_seconds', 300),
                $this->intConfig('cbox-id.otp.max_attempts', 5),
                $this->intConfig('cbox-id.otp.issue.max_per_window', 5),
                $this->intConfig('cbox-id.otp.issue.per_recipient_max', 10),
                $this->intConfig('cbox-id.otp.issue.window_seconds', 3600),
                $this->intConfig('cbox-id.otp.verify.max_per_window', 20),
                $this->intConfig('cbox-id.otp.verify.per_recipient_max', 15),
                $this->intConfig('cbox-id.otp.verify.window_seconds', 900),
            );
        });
    }

    /**
     * Text messages: the provider driver, the toll-fraud guard in front of it, the
     * localised message, and the dispatcher that ties them together and audits each send.
     * Nothing here touches a provider or reads a credential until the first text is sent.
     */
    private function registerSms(): void
    {
        $this->app->singleton(PhoneNumberNormaliser::class);
        $this->app->singleton(SmsSenderFactory::class);

        $this->app->singleton(SmsSender::class, static function (Application $app): SmsSender {
            $driver = config('cbox-id.sms.driver');

            return $app->make(SmsSenderFactory::class)->make(is_string($driver) && $driver !== '' ? $driver : 'log');
        });

        $this->app->singleton(SmsSendGuard::class, function (Application $app): SmsSendGuard {
            $countries = config('cbox-id.sms.allowed_countries');

            return new RateLimitedSmsSendGuard(
                $app->make(RateLimiter::class),
                is_array($countries) ? array_values(array_filter(array_map(
                    static fn (mixed $country): string => is_string($country) ? strtoupper(trim($country)) : '',
                    $countries,
                ))) : [],
                $this->intConfig('cbox-id.sms.limits.cooldown_seconds', 30),
                $this->intConfig('cbox-id.sms.limits.per_number_per_day', 10),
                $this->intConfig('cbox-id.sms.limits.per_ip_per_hour', 10),
                $this->intConfig('cbox-id.sms.limits.per_environment_per_day', 1000),
                $this->intConfig('cbox-id.sms.limits.daily_cap', 5000),
            );
        });

        $this->app->bind(SmsMessageComposer::class, static function (): SmsMessageComposer {
            $name = config('cbox-id.sms.app_name');
            $messages = config('cbox-id.sms.messages');

            $overrides = [];

            foreach (is_array($messages) ? $messages : [] as $locale => $template) {
                if (is_string($locale) && is_string($template) && $template !== '') {
                    $overrides[strtolower(str_replace('-', '_', $locale))] = $template;
                }
            }

            return new SmsMessageComposer(is_string($name) && $name !== '' ? $name : 'Cbox ID', $overrides);
        });

        $this->app->singleton(SmsDispatcher::class);
    }

    /**
     * The configured `key => channel-class` map, keeping only entries whose class
     * genuinely implements {@see OtpChannel} — an invalid entry is dropped, never
     * trusted, so the registry stays deny-by-default.
     *
     * @return array<string, class-string<OtpChannel>>
     */
    private function channelMap(): array
    {
        $configured = config('cbox-id.otp.channels');

        if (! is_array($configured)) {
            return [];
        }

        $map = [];

        foreach ($configured as $key => $class) {
            if (is_string($key) && is_string($class) && is_a($class, OtpChannel::class, true)) {
                $map[$key] = $class;
            }
        }

        return $map;
    }

    /**
     * Code length, clamped to a sane numeric-OTP range. The floor is 6 digits: a
     * shorter code (a 10^4 space) is brute-forceable within the per-challenge attempt
     * cap once an attacker sprays across recipients/IPs, so we refuse to configure one
     * below the NIST-recommended minimum. Above 10 overflows the generator's integer draw.
     */
    private function clampedLength(): int
    {
        return max(6, min(10, $this->intConfig('cbox-id.otp.code_length', 6)));
    }

    private function intConfig(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * Decode the crypto master key, tolerating Laravel's `base64:` prefix — the same
     * decode {@see CryptoServiceProvider} uses.
     */
    private static function decodeKey(string $configured): string|false
    {
        if ($configured === '') {
            return false;
        }

        if (str_starts_with($configured, 'base64:')) {
            $configured = substr($configured, 7);
        }

        return base64_decode($configured, true);
    }
}
