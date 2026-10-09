---
title: Offer SMS as a second factor
description: Let people enrol a phone number and receive sign-in codes by text — off by default, per environment, with the number sealed at rest
weight: 11
---

# Offer SMS as a second factor

`Identity\Contracts\SmsFactors` adds a phone number as a second factor next to TOTP and
passkeys: enrol it (prove it with a texted code), challenge with it at sign-in, remove it.
It is **off in every environment until that environment's policy turns it on**, because
SMS is the weakest factor the platform offers — see [Honest limits](#honest-limits).

Texts go through the SMS dispatcher, so the provider, the toll-fraud guard and the audit
rows are those described in [Send one-time codes by SMS](add-an-sms-otp-channel.md).
Configure a provider there first.

## 1. Turn it on for an environment

```php
use Cbox\Id\Identity\Contracts\SmsFactorPolicies;
use Cbox\Id\Identity\ValueObjects\SmsFactorPolicy;

app(SmsFactorPolicies::class)->setForEnvironment(new SmsFactorPolicy(
    enabled: true,
    allowedCountries: ['DK', 'SE', 'NO'],   // empty admits NO country
    privilegedNeedStrongerFactor: true,     // the default
));
```

- **`allowedCountries`** — the numbers that may enrol and be texted. Turning SMS on is also
  choosing where to send it; an empty list admits nothing. It is checked again at every
  send, so narrowing it stops texts to the removed countries at once. The deployment's
  `CBOX_ID_SMS_ALLOWED_COUNTRIES` still applies on top.
- **`privilegedNeedStrongerFactor`** — SMS cannot be an administrator's only factor. An
  administrator may add SMS only next to an authenticator app or a passkey; one who holds
  SMS alone (promoted after enrolling, or who removed their app) can still sign in with it
  — refusing would leave them a password alone — but `MfaMandate::requiresEnrolment()`
  answers `true` for them until they enrol a stronger factor, even where MFA is optional.
  Who is an administrator is `Identity\Contracts\PrivilegedSubjects`: by default an owner or
  admin of any organization; bind your own to widen it.

The policy is environment-level only: whether the deployment texts a country is a cost and
fraud decision for whoever pays the SMS bill.

## 2. Enrol

```php
use Cbox\Id\Identity\Contracts\SmsFactors;

$sent = app(SmsFactors::class)->beginEnrolment(
    $userId, $request->input('phone'), defaultCountry: 'DK', ip: $request->ip(), locale: app()->getLocale(),
);
// "We sent a code to {$sent->maskedNumber}"

app(SmsFactors::class)->confirmEnrolment($userId, $request->input('code'), $request->ip()); // bool
```

`beginEnrolment()` throws `SmsFactorRefused` (`reason`: `not_enabled`, `invalid_number`,
`country_not_allowed`, `stronger_factor_required`, `already_enrolled`) before anything is
stored or sent, and lets `OtpRateLimitExceeded`, `SmsSendRefused` and `SmsDeliveryFailed`
through. Starting again replaces an unconfirmed number; a confirmed one must be removed
first.

Recovery codes are separate (`Mfa::generateRecoveryCodes()`) and unaffected: generate them
after the first factor is confirmed, as you do for TOTP.

## 3. Challenge at sign-in

```php
$sms = app(SmsFactors::class);

if ($sms->isUsable($userId)) {             // confirmed AND accepted by the policy now
    $sent = $sms->sendChallenge($userId, $request->ip(), app()->getLocale());
}

$sms->verifyChallenge($userId, $code, $request->ip()); // single use
```

Count failures against your sign-in lockout as you do for TOTP codes — the factor caps
attempts per code and per recipient, but the account lockout is the host's.

`isEnrolled()` is "a confirmed number is on file"; `isUsable()` adds "and the policy accepts
it now". Use `isUsable()` to decide whether to offer SMS, and count an SMS factor as a
second factor only while it is usable — `DatabaseMfaMandate` does exactly that.

## 4. Show and remove

```php
$details = $sms->details($userId);   // maskedNumber, country, confirmed, confirmedAt — never the number
$sms->remove($userId, ActorType::Operator, $adminId);  // audited as user.mfa_sms_removed
```

`Mfa::disable()` (the full reset) removes the SMS factor with every other factor.

## What is stored

The factor is an `mfa_factors` row of type `sms`. The number is sealed in
`secret_encrypted` under the person's context (`cbox-id:mfa:{user_id}`), so key rotation
(`cbox-id:crypto:rewrap`) and erasure cover it with no new registration. OTP challenges
for it are addressed to `mfa-sms:{factor id}` — the challenge table, the `otp.issued` audit
row and the rate-limit keys hold an opaque id, never the number. The policy is a row in
`sms_factor_policies`.

## Honest limits

- **SIM swap and port-out.** Whoever controls the number receives the code. Carriers can
  be talked into moving a number.
- **Interception.** SS7 weaknesses let a well-resourced attacker read texts in transit.
- **Phishing.** A fake sign-in page can ask for the code and replay it within its
  lifetime. A passkey cannot be phished this way; a texted code can.
- **Cost.** Every text costs money, which is why the toll-fraud guard exists. Set provider
  spend limits too.

SMS is still far better than a password alone. Offer it for people who cannot use an
authenticator app or a passkey, keep administrators on stronger factors, and keep the
country list short.
