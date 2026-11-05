---
title: Authentication assessment
weight: 45
description: Apply a bounded host risk policy before creating a session or user token.
---

# Authentication assessment

Bind `Cbox\Id\Identity\Contracts\AuthenticationAssessment` in your host to consult an additional risk policy. The package has no risk-service dependency and makes no remote requests itself. Without this optional binding, existing ID policy applies.

`assertAllowed(VerifiedAuthentication $authentication)` receives the server-owned subject, organization, authentication methods, authentication time and issuance kind. Session creation also supplies its IP and user agent. Token grants can have an unknown authentication time and an empty method list; neither is proof of a fresh second factor. Machine client credentials do not invoke this user policy.

Return to continue ordinary policy, or throw `AuthenticationStepUpRequired` with your assessment identifier. Session creation then writes no session. User token issuance translates this exception to `invalid_grant` and creates no token. An allowing assessment does not override inactive-user, MFA, scope, audience or other existing checks. Token assessment runs before the issuer opens its mint transaction; callers may already have their own transaction.

The host owns a strict network deadline, tenant-scoped credentials, coverage and expiry checks, and its outage policy. For ordinary login, a remote timeout may fall back to existing ID policy. Sensitive operations must independently enforce their own fresh authentication requirement. Do not convert an assessment outage into proof of identity or disable local MFA.

For interactive login, handle the step-up exception by continuing the host's existing factor challenge or recovery/deny flow. Never issue a temporary authenticated session to represent a pending factor. Store handled signal revisions and the achieved assurance in server-controlled state to prevent challenge loops. The package does not ship a Signals adapter or that UI.

This hook does not retroactively invalidate an already issued JWT. Offline JWT validation remains valid until expiry unless the relying party separately uses supported revocation/introspection controls. Reassess on a later issuance or protected action; a webhook is a trigger for reevaluation, not an authentication result.

For tests, `FakeAuthenticationAssessment` accepts an explicit list of decisions: `null` continues ordinary policy, an `AuthenticationStepUpRequired` instance refuses it. Calls are recorded and exhausting the decisions throws instead of silently allowing authentication.

A completed session's existing `user.session_started` event includes `user_id`, `session_id` and the verified `amr`. It is distinct from the assessment and is emitted only after the session is saved. Hosts can decorate the event bus to add permitted context to this durable public feed; the event remains subject to its original environment and organization scope.
