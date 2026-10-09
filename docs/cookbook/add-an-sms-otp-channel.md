---
title: Send one-time codes by SMS
description: Turn on the shipped SMS channel — Twilio, MessageBird, Bird or 46elks over HTTP — with the toll-fraud controls every send passes
weight: 10
---

# Send one-time codes by SMS

The package ships an SMS channel, `Otp\Channels\SmsOtpChannel`, and four provider
drivers that talk HTTP through Laravel's client — no provider SDK is a dependency. Every
text passes a toll-fraud guard first and is audited with the number masked.

To use SMS as a **second factor** (enrol a number, challenge at sign-in), see
[Offer SMS as a second factor](offer-sms-as-a-second-factor.md) instead — it uses its own
channel so the number is stored sealed, never in the OTP tables.

## 1. Pick a provider

`.env`:

```dotenv
CBOX_ID_SMS_DRIVER=twilio          # twilio | messagebird | bird | 46elks | log | array
CBOX_ID_SMS_ALLOWED_COUNTRIES=DK,SE,NO,FI   # set it: see "Toll fraud" below

# Twilio — a Messaging Service is preferred over a single From number
TWILIO_ACCOUNT_SID=AC…
TWILIO_AUTH_TOKEN=…
TWILIO_MESSAGING_SERVICE_SID=MG…   # or TWILIO_FROM=+45…
```

| Driver | API | Settings (`cbox-id.sms.drivers.*`) |
|---|---|---|
| `twilio` | Programmable Messaging, `POST /2010-04-01/Accounts/{sid}/Messages.json` | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` (or `TWILIO_API_KEY` + `TWILIO_API_SECRET`), `TWILIO_MESSAGING_SERVICE_SID` or `TWILIO_FROM` |
| `messagebird` | MessageBird REST, `POST /messages` | `MESSAGEBIRD_ACCESS_KEY`, `MESSAGEBIRD_ORIGINATOR` |
| `bird` | Bird Channels API, `POST /workspaces/{ws}/channels/{ch}/messages` | `BIRD_ACCESS_KEY`, `BIRD_WORKSPACE_ID`, `BIRD_CHANNEL_ID` |
| `46elks` | `POST /a1/sms` | `ELKS_API_USERNAME`, `ELKS_API_PASSWORD`, `ELKS_FROM`, `ELKS_DRY_RUN` |
| `log` | none — writes the message, code included, to the log | **refused when `APP_ENV=production`** |
| `array` | none — keeps messages in memory | tests |

Every driver also takes a `*_BASE_URL` (a regional edge, a local double). Credentials are
read at the first send, so a deployment that never texts never needs them. Senders do not
retry: a retry after a timeout can deliver and bill twice, and the person waiting can press
"resend", which goes back through the guard.

Your own gateway: implement `Otp\Sms\Contracts\SmsSender` and put its class name in
`CBOX_ID_SMS_DRIVER`. It inherits every control below without implementing any.

## 2. Map the channel and issue

```php
// config/cbox-id.php
'otp' => ['channels' => [
    'email' => \Cbox\Id\Otp\Channels\EmailOtpChannel::class,
    'sms'   => \Cbox\Id\Otp\Channels\SmsOtpChannel::class,
]],
```

```php
$challenge = app(OtpService::class)->issue('login', '+45 12 34 56 78', 'sms', $request->ip());
```

The recipient may be formatted (`+45 12 34 56 78`, `0045…`, `+44 (0)20…`); it is
normalised to E.164 by `Otp\Sms\PhoneNumberNormaliser`, which also assigns the country.
A number it cannot place in a country is refused (`InvalidPhoneNumber`). Note that the OTP
module stores the recipient — here the phone number — in `otp_challenges.recipient`, as it
does an email address.

The text is written in the request's locale (`en`, `da`, `de`, `fr`, `nb`, `sv` ship;
others fall back to English), code first, inside one GSM-7 segment. Override any language
under `cbox-id.sms.messages` with `:code`, `:app` and `:minutes`.

## 3. Toll fraud

SMS pumping: an attacker drives a public "text me a code" form at premium-rate number
ranges and shares the revenue with whoever terminates them. Every send passes
`Otp\Sms\Contracts\SmsSendGuard` (`RateLimitedSmsSendGuard`) before the provider is
called, and nothing is counted when it refuses:

| Control | Setting | Default |
|---|---|---|
| Country allow-list (deployment) | `CBOX_ID_SMS_ALLOWED_COUNTRIES` | empty = no deployment restriction |
| Non-geographic ranges (`+881`, `+882`, `+883`, `+979`, …) | — | always refused |
| One text per number per … | `CBOX_ID_SMS_COOLDOWN_SECONDS` | 30 |
| Texts per number per day (per environment) | `CBOX_ID_SMS_PER_NUMBER_PER_DAY` | 10 |
| Texts per requesting IP per hour (per environment) | `CBOX_ID_SMS_PER_IP_PER_HOUR` | 10 |
| Texts per environment per day | `CBOX_ID_SMS_PER_ENVIRONMENT_PER_DAY` | 1000 |
| Texts per deployment per day — the circuit breaker | `CBOX_ID_SMS_DAILY_CAP` | 5000 |

On top of these, the OTP module's own issue caps apply (`cbox-id.otp.issue.*`).

A refusal throws `Otp\Sms\Exceptions\SmsSendRefused` with a `reason`
(`SmsRefusalReason`) and `retryAfterSeconds`. Every send is audited: `sms.sent` (provider,
message id), `sms.refused` (reason), `sms.failed` — each with the number masked
(`+45 ******78`), its country, the purpose and the IP. Pumping shows up as a pattern on
those rows without the rows holding the numbers.

The counters live in the cache store: it must be shared between replicas, or each replica
has its own budget. Also set spend limits and geo-permissions at the provider; they are
the last line, and they do not depend on this package being configured right.

## Testing

```php
use Cbox\Id\Otp\Sms\Testing\InteractsWithSms;

$sms = $this->fakeSms();                // binds an ArraySmsSender
// … drive the flow …
$sms->assertSent('+4512345678');
$code = $sms->latestCode();
```

For the driver itself, `Http::fake()` the provider host — the drivers use Laravel's HTTP
client.

## Honest limits

- SMS is the weakest second factor: SIM swap, number port-out, SS7 interception and
  real-time phishing relays all take the code. See [Security: OTP](../security/otp.md).
- The normaliser knows calling codes, the North American area codes that are not the US,
  and lengths for common European plans. It does not know which ranges are allocated;
  the provider rejects those.
