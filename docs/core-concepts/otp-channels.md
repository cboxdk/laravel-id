---
title: OTP delivery channels
description: Delivered one-time passcodes (email/SMS) as a verification and MFA factor — and the caps that make a short code safe
weight: 10
---

# OTP delivery channels

The OTP module (`Cbox\Id\Otp\`) issues and verifies short-lived, single-use
one-time passcodes delivered over a **channel** — email, SMS, or anything a host
wires — as a **verification** or **MFA** factor. It sits alongside the
authenticator-app TOTP factor, passkeys, and magic links, and is designed to be
composed by a host into its own "email me a code" / "text me a code" flows. It
ships no UI.

## Mental model

Three collaborators, all resolved from contracts:

- **`Contracts\OtpService`** (`DatabaseOtpService`) — the primitive. `issue()`
  generates a code, stores only its hash, and hands the plaintext to a channel for
  delivery; `verify()` / `verifyLatest()` check a presented code.
- **`Contracts\OtpChannel`** — a transport that delivers one code to one
  recipient. The package ships `EmailOtpChannel` (over the framework mailer), plus
  `LogOtpChannel` and `NullOtpChannel` for local dev and tests.
- **`Contracts\OtpChannels`** — a **deny-by-default** registry mapping a channel
  key (`email`, `sms`, …) to its sender. A key with no registered sender is
  **refused**, never a silent no-op.

```php
$challenge = app(OtpService::class)->issue(
    purpose: 'login',
    recipient: 'alice@example.com',
    channel: 'email',
    ip: $request->ip(),
);

// later, with the code the user typed:
$result = app(OtpService::class)->verify($challenge->id, $code, $request->ip());
if ($result->verified) {
    // step-up / second factor / contact confirmed
}
```

`issue()` returns an `OtpChallenge` value object describing the challenge — its id,
purpose, channel, recipient, expiry and attempt budget. It **never** contains the
code: the code travels only to the channel.

## The security guarantees

A delivered OTP is only as strong as the controls around it. The module makes all
of these structural:

- **Hashed at rest.** Only a **keyed HMAC** of the code is stored (`code_hash`) —
  never the plaintext. The HMAC key is derived (HKDF) from the crypto master key,
  which lives outside the database, so a database dump alone does not reveal codes.
  (See [security/otp.md](../security/otp.md) for why a *keyed* hash, not bcrypt or
  a plain hash, is the right choice for a low-entropy code.)
- **Single-use.** A verified challenge is marked `consumed_at` under a row lock in
  the same transaction; a second verify of the same code fails.
- **TTL-bounded.** A code expires after a short window (default 5 minutes); past
  that it fails.
- **Attempt-capped.** Each wrong guess increments `attempts`; at the cap (default
  5) the challenge locks and even the correct code fails — the host must re-issue.
- **Rate-limited, in layers.** Issuance is throttled both per
  recipient+purpose+IP *and* per recipient across all purposes and IPs — the
  second cap is what actually stops bombing / SMS-cost abuse when an attacker
  rotates the purpose or source IP to slip past the first. Verification is
  throttled globally per IP *and*, on the `verifyLatest()` recipient path, per
  recipient+purpose across IPs, so a recipient's live code cannot be brute-forced
  by spraying from many addresses. Underneath both sits the at-rest per-challenge
  attempt cap — the last-resort bound that holds even if the cache-backed limiter
  is unavailable.
- **`verifyLatest()` acts only on a LIVE, unlocked challenge.** The recipient-path
  finder selects the newest challenge that is unconsumed, unexpired *and* under its
  attempt cap. A locked or expired challenge is skipped rather than returned, which
  (a) keeps the recipient path uniform — no `expired`/`locked` status leaks as an
  enumeration signal — and (b) stops an attacker from shadowing a still-valid code
  by locking a fresher challenge for the same recipient.
- **No enumeration, no timing oracle.** A wrong code and an unknown recipient
  return the **same** uniform result, and the constant-time hash compare runs on
  every path — including when no challenge is found (against a decoy hash) — so
  neither the result nor the timing tells an attacker whether a recipient exists.
- **Environment-owned.** `Models\OtpChallenge` is `BelongsToEnvironment`: a
  challenge issued in one environment is structurally invisible to any other.

## Honest scope

- **A 6-digit code has ~2^20 of entropy.** Its safety rests on the **caps** above —
  the TTL, the per-challenge attempt cap, and the verify rate limit — *not* on the
  code being hard to guess. Keep those caps tight; lengthening the code is a weak
  substitute.
- **SMS is only as secure as SIM-swap resistance.** An SMS OTP can be intercepted
  by SIM-swap or SS7 attacks and by on-device malware. Treat SMS as a
  *step-up*/recovery convenience, and prefer a phishing-resistant factor (a
  passkey, or authenticator-app TOTP) as the primary. This package delivers the
  code; it cannot make the SMS channel itself trustworthy.
- **This is a primitive, not a policy.** Whether an emailed code counts as a
  sufficient second factor for a given action is the host's decision.

## Where to go next

- [Add an SMS OTP channel](../cookbook/add-an-sms-otp-channel.md) — wire your
  provider behind the contract.
- [Custom OTP channel](../extension-points/custom-otp-channel.md) — the extension
  point in detail.
- [Security: OTP](../security/otp.md) — the threat model and crypto rationale.
