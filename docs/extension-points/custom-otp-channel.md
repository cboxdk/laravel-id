---
title: Custom OTP channel
description: The OtpChannel / OtpChannels extension point — swap, add, or decorate how OTP codes are delivered
weight: 5
---

# Custom OTP channel

Delivery of a one-time passcode is fully pluggable through two contracts:

- **`Contracts\OtpChannel`** — a single transport. `deliver(OtpDelivery $delivery)`
  sends one code to one recipient.
- **`Contracts\OtpChannels`** — the **deny-by-default** registry. It maps a channel
  key to a sender; an unregistered key is refused (`UnknownOtpChannel`), never a
  silent no-op.

## The `OtpDelivery` value object

Everything a channel needs, and the only place the plaintext code travels after
generation:

| Property        | Meaning                                             |
| --------------- | --------------------------------------------------- |
| `challengeId`   | The challenge this code belongs to                  |
| `recipient`     | Email address / phone number / handle               |
| `code`          | The plaintext code — deliver, then discard          |
| `purpose`       | The host-defined purpose (`login`, `step_up`, …)    |
| `channel`       | The channel key it was issued under                 |
| `expiresAt`     | Absolute expiry (`DateTimeImmutable`)               |
| `ttlSeconds`    | TTL in seconds; `ttlMinutes()` rounds up for prose  |

A channel **must not** persist, durably log, or echo the code anywhere it would
outlive the message.

## Registering a channel

Two ways, both honouring deny-by-default:

**Config (the usual path).** List `key => class` under `cbox-id.otp.channels`; the
class must implement `OtpChannel`. Invalid entries are dropped, never trusted.

```php
'otp' => ['channels' => ['sms' => \App\Otp\SmsOtpChannel::class]],
```

**At runtime.** Register a ready instance — useful for hosts wiring a pre-built
client, and how the test trait injects a fake:

```php
app(Cbox\Id\Otp\Contracts\OtpChannels::class)
    ->register('sms', new \App\Otp\SmsOtpChannel($client));
```

## Shipped channels

- **`EmailOtpChannel`** — a plain-text email over the framework `Mailer` contract
  (no dependency forced; no marketing; the code appears only in that one message).
  Subject and from-address come from `cbox-id.otp.email.*`.
- **`LogOtpChannel`** — writes the code to the log. **Local development only** —
  it deliberately does the one thing the rest of the module avoids. Never register
  it in production.
- **`NullOtpChannel`** — discards the code. A deliberately-registered black hole
  for tests; note this is *opt-in*, distinct from the deny-by-default refusal of an
  *unregistered* key.

## Decorating an existing channel

Because channels are resolved from the registry, you can wrap one — e.g. to add
per-tenant branding, a delivery-metrics counter, or a send-time allow-list — by
registering a decorator that delegates to the shipped channel:

```php
class BrandedEmailChannel implements OtpChannel
{
    public function __construct(private readonly EmailOtpChannel $inner) {}

    public function deliver(OtpDelivery $delivery): void
    {
        // ... pre-processing ...
        $this->inner->deliver($delivery);
    }
}
```

## Testing your channel

Use `Testing\InteractsWithOtp` and `Testing\FakeOtpChannel` to exercise issuance
without a live transport — `FakeOtpChannel` captures every delivery so a test can
read back the code. See [getting-started/testing.md](../getting-started/testing.md).
