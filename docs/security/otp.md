---
title: OTP
description: Threat model and crypto rationale for delivered one-time passcodes — hashed-at-rest, single-use, TTL, attempt-cap, rate-limit, no enumeration
weight: 13
---

# Security: OTP

Delivered one-time passcodes (`Cbox\Id\Otp\`) are an **auth factor**, so their
controls are load-bearing. This page states the threat model, the crypto choices,
and the honest limits.

## What makes a short code safe

A 6-digit numeric code lives in a ~10^6 (≈ 2^20) space. It is **not** safe because
it is hard to guess — it is safe because of the **caps** around it. Get the caps
right and the code length is almost incidental:

| Control            | Mechanism                                                        | Where |
| ------------------ | ---------------------------------------------------------------- | ----- |
| Hashed at rest     | keyed HMAC of the code; raw code never stored                    | `KeyedOtpHasher`, `Models\OtpChallenge` |
| Single-use         | `consumed_at` set under a row lock in the verify transaction     | `DatabaseOtpService::settle()` |
| TTL                | `expires_at` (default 5 min); expired codes fail                 | `DatabaseOtpService`, config `otp.ttl_seconds` |
| Attempt cap        | `attempts` vs `max_attempts` (default 5); then the challenge locks | `DatabaseOtpService::settle()` |
| Issue throttle     | per recipient+purpose+IP **and** per recipient (all purposes/IPs) — the latter bounds bombing when the attacker rotates purpose/IP | `DatabaseOtpService::issue()`, config `otp.issue.max_per_window`, `otp.issue.per_recipient_max` |
| Verify throttle    | global per-IP **and** (recipient path) per recipient+purpose across IPs | `DatabaseOtpService::verifyThrottled()` / `verifyRecipientThrottled()`, config `otp.verify.max_per_window`, `otp.verify.per_recipient_max` |
| Live-only recipient finder | `verifyLatest()` targets only the newest unconsumed, unexpired, under-cap challenge — a locked/expired one is skipped, not returned | `DatabaseOtpService::verifyLatest()` |
| Minimum code length | config below 6 digits is floored to 6 (a 10^4 space is refused) | `OtpServiceProvider::clampedLength()`, config `otp.code_length` |
| No enumeration     | wrong code and unknown recipient give the same uniform result   | `OtpResult`, `OtpFailureReason` |
| No timing oracle   | constant-time compare runs on every path, incl. the miss (decoy) | `DatabaseOtpService::settle()`, `OtpHasher::decoy()` |
| Environment scope  | `BelongsToEnvironment` — cross-env verify is impossible          | `Models\OtpChallenge` |

## Why a *keyed* hash, not bcrypt or a plain hash

The at-rest value must survive a database dump. Two properties are in tension:

- A **plain fast hash** (SHA-256) of a 6-digit code is useless at rest: an attacker
  who dumps the table brute-forces the ~10^6 space in well under a second.
- A **slow password hash** (bcrypt/argon2) would fix the at-rest problem, but it is
  hit on **every verify attempt** — turning the attempt cap and rate limiter into a
  CPU-amplification lever (each guess costs a full bcrypt) and adding a DoS surface
  on the verify path.

So the module uses a **keyed HMAC** (`hash_hmac('sha256', code, subkey)`), where the
subkey is derived via **HKDF** from the crypto **master key** — the same key class
that seals MFA secrets, held in config / a secret store, **not** in the database. A
dump therefore does not reveal codes: an attacker needs the master key too, and
even with both the online caps and the 5-minute TTL still bound the attack. The
HMAC compare is cheap and constant-time, so the **caps** — not hash slowness — do
the security work, which is exactly where the guarantee should rest.

All primitives are vetted PHP core (`random_int`, `hash_hkdf`, `hash_hmac`,
`hash_equals`); nothing is hand-rolled.

## No enumeration, no oracle

`verify()` returns a uniform `OtpResult`. A **wrong code** and an **unknown /
consumed challenge** both return `Invalid` — the reason never lets a caller probe
which recipients or challenges exist. `Expired` and `Locked` are returned only to a
caller that already presented a valid challenge id (not an enumeration signal), so a
host can still prompt "request a new code". Crucially, the constant-time hash
compare runs on **every** path, including when no challenge is found (against a
decoy hash), so timing does not distinguish a miss from a wrong guess.

The plaintext code appears in exactly one place — the `OtpDelivery` handed to the
channel. It is never returned to the caller, never written to an audit row, and
never placed in an exception message.

## Honest limits

- **The code's entropy is not the control.** Do not rely on length; rely on the TTL
  + attempt cap + verify throttle. Those are the invariants to protect in review.
- **SMS is only as secure as SIM-swap resistance.** SMS OTPs can be intercepted via
  SIM-swap, SS7, or device malware. Prefer a phishing-resistant primary factor
  (passkey / authenticator TOTP) and treat SMS as step-up or recovery. This package
  delivers the code; it cannot make the SMS bearer channel trustworthy.
- **Email OTP inherits email's trust.** A code emailed to a compromised mailbox is
  compromised. Email OTP is a *possession-of-inbox* check, not a strong factor.
- **This is a primitive.** Whether an OTP satisfies a given step-up policy is the
  host's decision; the module enforces the mechanics, not the policy.

## Operational caveats

Two guarantees depend on how the host deploys the module:

- **The single-use / attempt-cap serialization needs a locking database.** `verify()`
  reads the challenge with `SELECT … FOR UPDATE` inside a transaction, so two
  concurrent verifies of the same code cannot both succeed. This holds on MySQL/MariaDB
  (InnoDB) and PostgreSQL. On engines that ignore row locks — **SQLite**, or `MyISAM`
  — the lock is a no-op and, under genuine concurrency, the single-use guarantee
  degrades to best-effort. Run OTP against a locking engine in production; SQLite is
  fine for tests but not for a live verify path.
- **The rate limiter needs a shared, persistent cache store.** The issue/verify caps
  live in Laravel's `RateLimiter` (the cache). With the `array` driver they reset every
  request and enforce nothing; with a per-node store they are not shared across app
  servers, so the effective limit multiplies by the node count. Point `cache.default`
  at a shared store (Redis/Memcached/database) so the caps are global. The at-rest
  per-challenge attempt cap is the one bound that survives a missing/again-reset
  limiter — it is enforced in the row, not the cache.
- **A queued mailer can still leak the code channel-side.** The plaintext code is
  never persisted by this module, but `EmailOtpChannel` hands it to the framework
  mailer; if that mailer is queued, the code is serialized into the **job payload**
  on your queue backend until the job runs. Keep the queue store as trusted as the
  mail transport, or deliver OTP mail synchronously.

## Auditing

Issuance (`otp.issued`), failed verifies (`otp.verify_failed`), lockouts
(`otp.locked`) and successful verifies (`otp.verified`) are recorded on the
hash-chained audit trail — with the challenge id, purpose, channel and recipient,
and **never** the code. See [core-concepts/audit-streaming.md](../core-concepts/audit-streaming.md).
