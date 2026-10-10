---
title: Password policy
description: Where the tenant's authentication policy is enforced, why it sits on the credential primitive, and what it deliberately does not cover
weight: 14
---

# Security: password policy

An **environment** sets the authentication baseline; an **organization** may layer its
own policy on top, but only to tighten it. `AuthPolicy::tightenedWith()` is the only
supported way the two combine, so a tenant can demand more of its own people than the
operator requires and never less.

That much was straightforward. The part worth writing down is *where the rules are
applied*, because the first implementation got it wrong in an instructive way.

## Enforcement sits on the primitive, not on the callers

`DatabaseSubjects::create()` and `DatabaseSubjects::setPassword()` call the
`PasswordPolicyGuard` themselves. Every path that sets a credential — signup, invitation
acceptance, self-service reset, administrative assignment, bulk import — reaches one of
those two methods, so every path inherits the policy without knowing it exists.

The first cut bolted the guard onto individual services instead. It was called from
`AdminPasswordService` and nowhere else, which meant an environment demanding 24
characters got 24 on administrative assignment and whatever floor the calling Livewire
form happened to hardcode — 12 — everywhere else, including the reset flow most people
actually use. Nothing was broken in the policy engine; the engine simply was not asked.

Putting the check where the credential is written inverts the default. A new caller has
to go out of its way to bypass the policy rather than out of its way to honour it.

## Inferring the organization

The primitive is handed a subject id and a password. It has no organization context, and
resolving the environment baseline alone would reopen the same hole from the other
direction: a member of a strict organization could satisfy the looser environment floor
through any path that did not happen to carry org context.

So when no organization is named, `PasswordPolicyEnforcer` resolves the environment
baseline tightened by **every** organization the subject belongs to. A subject bound by
two organizations must satisfy both.

A caller that *does* know the organization should still pass it.
`AdminPasswordService` does, because an administrator seeding a password for someone
being invited into a strict organization is not yet a member of it — the primitive cannot
infer what has not happened yet. Both checks run and the stricter wins.

## Surfacing the refusal

`PolicyViolation` is an exception, which is right for a primitive and wrong for a form.
Forms that set a password should use `Identity\Rules\PasswordMeetsPolicy` so the refusal
lands on the field the person is typing into. It should replace a hardcoded `min:` rule
rather than sit beside one — a fixed number cannot know what the tenant requires, and
having both means the smaller one silently defines the UX.

## What plaintext import means

Bulk import distinguishes two cases, and the policy binds only one of them:

- A **password hash** from another IdP goes through `storeCredential()` verbatim. There
  is no plaintext to inspect, so no rule can apply. This is the normal migration route.
- A **plaintext password** in an import file goes through `create()`, and the policy
  applies. A row whose password is below the floor is reported as a per-row import error,
  not a crash.

If you have plaintext, you are seeding accounts rather than migrating them, and seeded
accounts should meet the same floor as any other.

## The three fields that are not about password strength

`AuthPolicy` also carries `maxAgeDays`, `mfa` and `lockoutThreshold`. Each is enforced by
a service of its own, because each fails differently when enforced naively.

### `maxAgeDays` — `PasswordExpiry`

Rotation needs to know when the password was last set, and the users table is host-owned,
so the platform keeps its own `password_ages` row, stamped by the same primitive that
applies the policy. A timestamp maintained by the callers is a timestamp some caller
forgets.

A subject with **no** recorded age does not expire. Their credential predating this being
tracked is not evidence of an old password, and locking them out on that assumption is a
worse failure than a clock that starts late. The migration seeds every existing subject
with the upgrade time so the clock starts for everyone at once rather than never.

Enforcement is a **hold on every authenticated request**, not a check at sign-in: an
already-open session would otherwise outlive the rotation it was supposed to trigger.

### `mfa` — `MfaMandate`

This is the one field that cannot be enforced by refusing something. Turning away a
subject who has no factor, on a policy that has just started requiring one, locks out
exactly the people who need to enrol. So the mandate is a question — "does this subject
still owe one?" — and the host holds them on the enrolment page until the answer is no.

A confirmed TOTP factor and a registered passkey both satisfy it. A passkey is usually
the stronger of the two, so treating it as not-a-factor would push people from a better
credential to a worse one to satisfy a policy meant to raise the bar.

### `lockoutThreshold` — `LoginAttempts`

Per **subject**, not per IP. The IP-keyed rate limiting the sign-in forms already do is a
different control: it protects the service from a flood, while an attacker spreading
guesses across a botnet never trips it and a shared office NAT trips it with nobody being
attacked at all.

The lock is checked **before** the credential, or a locked account still tells an attacker
which guess was right.

**On by default.** When no environment or organization policy names a threshold, the
deployment default applies: `cbox-id.lockout.threshold`, 10 unless you change it
(`CBOX_ID_LOCKOUT_THRESHOLD`). A policy that names a threshold wins over the default; an
organization may still only tighten its environment's. Set the default to `0` to go back
to "off unless a policy says so" — the behaviour before 1.22, when a fresh install
accepted an unbounded guessing run against any one account.

Two durations are deliberately not policy fields. They are deployment configuration
(`cbox-id.lockout.window_minutes` and `cbox-id.lockout.duration_minutes`), never tenant
policy:

- The counting **window** (15 minutes). Failures spread thinly over weeks are not an
  attack in progress, and counting them forever locks out people who occasionally mistype.
- The lockout **duration** (15 minutes). A lock that lasts until an administrator
  intervenes is a denial-of-service tool — anyone who knows an email address can lock its
  owner out at will. NIST SP 800-63B prefers throttling to hard lockout for this reason:
  the threshold exists to make guessing impractical, not to punish.

## The environment-wide fields

Five fields on `AuthPolicy` are not about passwords and are never an organization's to
change. They are decided where the organization is usually not known yet — the sign-in
page before an address is typed, a session read on every request — so a per-organization
answer could not be enforced honestly. `tightenedWith()` keeps the **baseline's** value for
each of them, whatever an organization's override row holds; `AuthPolicy::environmentWide()`
names them.

| Field | Default | What it decides |
|---|---|---|
| `passkeys` | on | Whether a passkey may be used to sign in, or be added |
| `magicLink` | on | Whether a one-time sign-in link may be emailed and redeemed |
| `sessionIdleMinutes` | null (the deployment's) | How long a session may sit unused |
| `sessionAbsoluteMinutes` | null (the deployment's) | How long a session lasts at most, however active |
| `botChallenge` | on | Whether the host may put a human check in front of an attempt its risk scoring flagged |

### The deployment is the ceiling

Read them through `Identity\Contracts\SignInMethods` (bound to `PolicySignInMethods`), not
from the policy directly. It combines the environment's choice with the deployment's
configuration, and the deployment wins:

- `cbox-id.sign_in.passkeys` and `cbox-id.sign_in.magic_link` (`CBOX_ID_PASSKEYS_ENABLED`,
  `CBOX_ID_MAGIC_LINK_ENABLED`, both on by default). Off here means off in every
  environment, whatever its policy says.
- `cbox-id.sessions.ttl_minutes` and `cbox-id.sessions.idle_minutes` are the longest an
  environment may choose. A longer choice is cut to the deployment's. Where the deployment
  sets no idle timeout (`0`), an environment's idle timeout is bounded by the absolute
  lifetime instead.

`botChallenge` has no framework-side ceiling: the challenge itself (Turnstile, hCaptcha,
whatever the host uses) is the host's, and so is the question of whether it is configured.

### Enforced on the primitives

`MagicLinkService::request()` and `redeem()`, and `PasskeyService::register()` and
`authenticate()`, throw `SignInMethodDisabled` (with `$method` set to `magic_link` or
`passkeys`) when the method is off. Redeeming refuses too, so a link minted before the
switch was turned off no longer works. A passkey refusal comes before the credential is
looked up, so a closed door answers the same for every credential id. Registered passkeys
are kept, and come back when passkeys are switched on again.

A host should ask `SignInMethods` first and not draw a method that is off; the exception is
what holds when it did not.

`DatabaseSessionManager` uses the environment's lengths. A new session's `expires_at` is
written with the environment's absolute lifetime, and `active()` applies the environment's
idle timeout. Where an environment has chosen an absolute lifetime, `active()` also measures
it from `created_at`, so shortening it ends long sessions that are already running.
