---
title: External actions & inline hooks
description: Synchronous extension points that can enrich or veto an operation — in-process handlers or signed, SSRF-guarded external HTTP calls
weight: 14
---

# External actions & inline hooks

Inline hooks (`Cbox\Id\ExternalActions\`) are **synchronous** extension points: at a
named point in a flow, the platform pauses and consults registered logic that can
**enrich** the operation (add data) or **veto** it (deny) — an inline-hook capability:
your code runs inside the auth pipeline, not after it.

It is deliberately different from [webhooks](audit-streaming.md): a webhook *notifies*
asynchronously and cannot change the outcome; a hook *participates* in-band and can.

## Hook points

Six, spanning the token, login, registration and credential flows. Each one names when
it fires, whether a deny stops anything, and what an *unreachable* hook means there:

| Hook point | Fires | Vetoes | Unreachable |
|---|---|---|---|
| `token_minting` | before an access token is signed, on every grant | yes | denies |
| `post_login` | after authentication, before the session row | yes | allows |
| `pre_registration` | before a subject is created | yes | denies |
| `post_registration` | just after, with the new subject id | no | allows |
| `pre_password_change` | before a credential is written | yes | denies |
| `post_password_change` | just after | no | allows |

Full payload shapes, fail policies and worked examples:
[Hook points](../extension-points/hook-points.md).

## Two kinds of action

**In-process** (dependency-light) — a class implementing `Contracts\Action`, listed in
config. Deny-by-default: only listed classes run.

```php
final class AddTenantTier implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        $tier = /* look up the org's plan */;

        return ActionResult::continue(['tenant_tier' => $tier]); // add a claim
        // or: return ActionResult::deny('org is over quota');   // veto
    }
}
```
```php
// config/cbox-id.php
'external_actions' => ['hooks' => ['token_minting' => [AddTenantTier::class]]],
```

**External HTTP** — register a customer HTTPS endpoint; the platform calls it
synchronously and interprets the JSON reply. The request is SSRF-guarded and HMAC-signed
(the same scheme as webhooks); the reply is
`{"action":"continue"|"deny","claims":{…},"reason":"…"}`.

```php
$registered = app(ExternalActions::class)->register(HookPoint::TokenMinting, 'https://hooks.acme.com/token');
// $registered->secret — the reveal-once HMAC secret the endpoint verifies X-Cbox-Signature with.
```

A hook point runs its in-process actions first, then its external endpoints, folding the
results: the first **deny** short-circuits; enrichment is merged (later wins).

## Fail policy: closed at the gates, open on the login path

If a hook can't be **consulted** — an in-process action throws, or an external endpoint
times out / errors / returns non-2xx — what happens is that hook point's decision. Every
gate (`token_minting`, `pre_registration`, `pre_password_change`) **denies**: a security
control that fails open is not a control. `post_login` **allows**, because failing closed
on the hottest path in the product hands one customer-controlled URL the power to lock a
whole tenant out of everything, admin console included; the notify-only points allow
because they have no decision to fail closed to.

A hook that *is* consulted and denies always denies. That is never configurable.

Override per point with `external_actions.fail_policy.<hook>` (`'open'` / `'closed'`), or
for all of them with `external_actions.fail_open` (a bool; leave it unset to keep the
per-point defaults).

## Honest scope

- **There is no separate `credentials_exchange` point.** `token_minting` already fires on
  the `client_credentials` grant; its payload's `grant` field is how you filter for it.
- **The external call is on the auth hot path.** Keep the endpoint fast — the timeout is
  short (default 3s) and there is **no retry** (a hook is synchronous, not a webhook). A
  fan-out of several endpoints goes out concurrently, so the whole pipeline costs one
  endpoint's timeout rather than one per endpoint.
- **Registration and password-change hooks are environment-scoped in practice.** Neither
  operation carries an organization, so only environment-level endpoints
  (`organization_id` null) fire for them. `token_minting` and `post_login` do carry one,
  and a tenant's own endpoints fire for it.
- **A hook cannot rewrite protocol claims.** `iss`, `sub`, `exp`, `scope`, `aud`, `cnf`,
  `ent`, … are protected; enrichment only adds non-reserved keys.
- **This is a primitive, not a policy.** What a hook decides is the host's logic; the
  platform guarantees the mechanics — deny-by-default, fail-closed, signed, SSRF-guarded,
  audited.

## Where to go next

- [Hook points](../extension-points/hook-points.md) — every point, payload and fail policy.
- [Add a token claims hook](../cookbook/add-a-token-hook.md) — the recipe.
- [Custom hook action](../extension-points/custom-action.md) — the contract in detail.
- [Security: external actions](../security/external-actions.md) — the threat model.
