---
title: Add an SMS OTP channel
description: Deliver one-time passcodes over SMS by wiring your own provider behind the OtpChannel contract
weight: 10
---

# Add an SMS OTP channel

The package ships an **email** OTP channel but **no SMS SDK** — SMS is a contract
only. To offer "text me a code", implement `Contracts\OtpChannel` around your
provider's client (Twilio, MessageBird, Vonage, an internal gateway — whatever you
already use) and register it under a channel key.

This keeps the dependency graph clean: the platform never pulls a provider SDK you
might not use, and you keep full control of the transport.

## 1. Implement the channel

A channel receives an `OtpDelivery` — the recipient, the plaintext code (once), the
purpose, and the expiry — and delivers it. It must not persist or log the code.

```php
namespace App\Otp;

use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;

class SmsOtpChannel implements OtpChannel
{
    public function __construct(private readonly \Twilio\Rest\Client $twilio) {}

    public function deliver(OtpDelivery $delivery): void
    {
        $this->twilio->messages->create($delivery->recipient, [
            'from' => config('services.twilio.from'),
            'body' => "Your code is {$delivery->code}. "
                ."It expires in {$delivery->ttlMinutes()} minute(s).",
        ]);
    }
}
```

> The example names a provider only to be concrete. Any transport works — the
> platform depends on the `OtpChannel` contract, never on a specific SDK.

## 2. Register it under a channel key

Add the key to `config/cbox-id.php`. The registry is **deny-by-default**: only keys
listed here (with a class that implements `OtpChannel`) are accepted.

```php
'otp' => [
    'channels' => [
        'email' => \Cbox\Id\Otp\Channels\EmailOtpChannel::class,
        'sms'   => \App\Otp\SmsOtpChannel::class,
    ],
],
```

Resolve any constructor dependencies (the Twilio client above) the usual way — a
binding in a service provider, or type-hints the container can autowire.

## 3. Issue over the channel

```php
$challenge = app(Cbox\Id\Otp\Contracts\OtpService::class)->issue(
    purpose: 'login',
    recipient: '+15551234567',
    channel: 'sms',
    ip: $request->ip(),
);
```

Verification is identical regardless of channel — you hold `$challenge->id` and
call `verify()`.

## Notes

- **Cost & abuse.** SMS costs money per message, which makes issuance a DoS and
  billing target. The per-recipient issue rate limit (`cbox-id.otp.issue.*`) is
  your first defence; tune it down for SMS if needed, and consider a separate,
  stricter purpose for SMS flows.
- **Trust.** SMS is susceptible to SIM-swap and interception — see
  [security/otp.md](../security/otp.md). Prefer it as a step-up/recovery option
  behind a phishing-resistant primary factor.
- **Phone-number validation and formatting (E.164) are the host's job** before
  calling `issue()`; the channel receives whatever recipient you pass.
