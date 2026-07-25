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

## What this does not cover

`AuthPolicy` also carries `mfa`, `lockoutThreshold` and `maxAgeDays`. Those are stored,
inherited and tightened correctly, but **no sign-in path reads them yet** — they describe
an intent the authentication flow does not act on. The console marks them as such rather
than presenting them as live controls. Treat them as unimplemented until this page says
otherwise.
