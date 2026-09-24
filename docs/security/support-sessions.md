---
title: Support sessions
description: Threat model for staff acting as a customer's user — the consent decision, act on every token, no refresh, no exchange, session-capped lifetimes and the limits of revocation
weight: 18
---

# Security: support sessions

A support session puts somebody else's hands on a customer's account. Everything below is
about keeping that bounded, visible and attributable. The feature is described in
[Staff roles & support access](../core-concepts/staff-and-support-access.md).

## Controls

| Control | Mechanism | Where |
| --- | --- | --- |
| Staff must be the vendor's staff | `support:impersonate` declared by **this app**, held through an **environment-wide** grant; a grant inside one organization does not count | `DatabaseStaffAccess::holdsEverywhere()` |
| Apps opt in | an app that never declares `support:impersonate` cannot be entered by staff | same |
| Target is a real, active member | active membership in an active organization; invited and suspended members refused | `SupportSessionService::begin()` |
| Reason required | blank refused; the reason is on both audit trails and in the customer's webhook | `SupportSessionService::begin()` |
| Only first-party, environment-owned apps | see *The consent decision* | `SupportSessionService::eligibleClient()` |
| Registered redirect URIs only | exact match on every code minted | `SupportSessionService::mint()` |
| Bounded lifetime | ≤ 60 minutes (config may only lower it); token and ID Token `exp` never pass the session's end | `SupportSessionService::ttl()`, `JwtTokenIssuer::lifetime()`, `TokenController::idTokenExpiry()` |
| The session is re-read | the token endpoint re-reads the session at redemption and checks actor, subject, client and organization; the code is a pointer, never the authority | `TokenController::actedAuthorizationCode()` |
| Every token names the actor | `act: {sub}` on access and ID Tokens, and in introspection; `act` is a reserved claim a token hook can neither forge nor rewrite | `JwtTokenIssuer`, `TokenController`, `IntrospectionController` |
| No renewal | never a refresh token; `offline_access` is removed from the session's scopes; token exchange refuses an acted subject token | `SupportSessionService::scopesFor()`, `TokenController`, `TokenExchangeService` |
| Ending kills what it issued | outstanding codes consumed, every access token minted for the session revoked | `SupportSessionService::end()` |
| Codes only for the session's actor | `issueCode()` binds the actor into the lookup | `SupportSessionService::issueCode()` |
| Both sides audited | `support_session.started` / `.ended` on the organization's trail and the environment's | `SupportSessionService::recordOnBothTrails()` |

## The consent decision

The person being acted as never agrees to a support session. Any app a support session can
mint tokens for therefore receives that person's data without their consent. That is
acceptable only where consent would not have been asked anyway, so a session is refused
unless the app is:

- **first-party** (`first_party` true), **and**
- **owned by the environment** (`organization_id` null), **and**
- registered for the **authorization-code** grant.

A third-party app would be handed a person's data on somebody else's say-so. A first-party
app a *customer* registered is that customer's own software, and the vendor's staff have no
business minting tokens into it. Both are refused with `ClientNotEligible`. There is no
"show a consent screen instead" fallback: the person whose consent it would be is not the
person at the keyboard.

No `auth_time`, `amr` or `acr` is asserted on an acted ID Token. Nobody authenticated as the
target, and a claim saying they did — or an assurance level derived from the actor's login —
would tell the app a login happened that did not.

## Why exchange is refused

Token exchange (RFC 8693) mints a fresh token for the subject of the one presented. Through
the ordinary path, that fresh token would carry no `act` — the app would believe the
customer was signed in themselves — and a new lifetime, exchangeable again before it
expired: a refresh token by another name. An acted subject token is refused with
`invalid_grant`. Delegation chains that carry `act` forward are not offered.

## Honest limits

- **Revocation is only as fast as the resource server checks.** `end()` revokes every token
  the session minted, so introspection reports them inactive immediately. A resource server
  that validates JWTs offline keeps accepting a token until its `exp` — which never passes
  the session's end, and is at most the client's access-token lifetime.
- **`EnvironmentAdmin` is the caller's assertion.** The framework cannot know who administers
  an environment; the host that passes `SupportActorKind::EnvironmentAdmin` must have checked.
- **The app decides what an acted user may do.** `act` tells the app who is really there; the
  app must use it to refuse what support must never do on a customer's behalf.
- **One app per session.** A session names one client; supporting a customer in two apps is
  two sessions, each audited.
- **The consent rule is fixed.** There is no switch that lets a support session reach a
  third-party app.
