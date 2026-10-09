<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Otp\Channels\SmsOtpChannel;
use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Contracts\SmsSendGuard;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;
use Cbox\Id\Otp\Sms\ValueObjects\PhoneNumber;
use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;
use Illuminate\Contracts\Container\Container;

/**
 * The one path every one-time code sent by text goes through — {@see SmsOtpChannel} for
 * a host's own flows, and the SMS second factor — so the controls cannot differ between
 * them: guard, compose in the recipient's language, send, audit.
 *
 * EVERY SEND IS AUDITED, refused ones too: `sms.sent` with the provider and its message
 * id, `sms.refused` with the reason, `sms.failed` when the provider would not take it.
 * The number is always MASKED on the row (`+45 ******78`) and the code never appears —
 * the audit log is exported to SIEMs and compliance archives that must not become a
 * phone book. Pumping shows up as a pattern on these rows (a run of refusals for one
 * country, many distinct numbers from one IP) without the rows holding the numbers.
 *
 * The sender, the guard and the composer are resolved from the container AT SEND TIME
 * rather than injected. The OTP channel registry builds its channels once and keeps them,
 * so anything captured here would outlive a changed binding: a test's fake sender, a
 * host's own guard bound after boot, a re-read config. Resolving per send costs nothing
 * next to an HTTP call to a provider.
 */
class SmsDispatcher
{
    public function __construct(
        private readonly Container $container,
        private readonly AuditLog $audit,
    ) {}

    /**
     * @param  list<string>|null  $allowedCountries  a narrower allow-list for this send (an environment policy)
     *
     * @throws SmsSendRefused
     * @throws SmsDeliveryFailed
     */
    public function sendCode(PhoneNumber $to, OtpDelivery $delivery, ?array $allowedCountries = null): void
    {
        $context = [
            'to' => $to->masked(),
            'country' => $to->country,
            'purpose' => $delivery->purpose,
            'channel' => $delivery->channel,
        ];

        try {
            $this->container->make(SmsSendGuard::class)->admit($to, $delivery->ip, $allowedCountries);
        } catch (SmsSendRefused $refused) {
            $this->record('sms.refused', $delivery, [...$context, 'reason' => $refused->reason->value]);

            throw $refused;
        }

        $sender = $this->container->make(SmsSender::class);
        $body = $this->container->make(SmsMessageComposer::class)->compose($delivery->code, $delivery->ttlMinutes(), $delivery->locale);

        try {
            $receipt = $sender->send(new SmsMessage($to, $body));
        } catch (SmsDeliveryFailed $failed) {
            $this->record('sms.failed', $delivery, [...$context, 'provider' => $sender->name()]);

            throw $failed;
        }

        $this->record('sms.sent', $delivery, [
            ...$context,
            'provider' => $receipt->provider,
            'message_id' => $receipt->messageId,
        ]);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    private function record(string $action, OtpDelivery $delivery, array $context): void
    {
        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            targetType: 'otp_challenge',
            targetId: $delivery->challengeId,
            context: $context,
            ip: $delivery->ip,
        ));
    }
}
