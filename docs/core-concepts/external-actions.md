---
title: External actions & inline hooks
description: Synchronous extension points that can enrich or veto an operation — in-process handlers or signed, SSRF-guarded external HTTP calls
weight: 14
---

# External actions & inline hooks

Inline hooks (`Cbox\Id\ExternalActions\`) are **synchronous** extension points: at a
named point in a flow, the platform pauses and consults registered logic that can
**enrich** the operation (add data) or **veto** it (deny). This is the Okta-inline-hook
/ Auth0-Actions capability.

It is deliberately different from [webhooks](audit-streaming.md): a webhook *notifies*
asynchronously and cannot change the outcome; a hook *participates* in-band and can.

## Hook points

v1 ships one, wired into the OAuth token flow:

- **`TokenMinting`** — runs just before an access token is signed, on every grant
  (client-credentials, authorization-code, refresh, device, CIBA). An action can add
  claims or veto issuance. Reserved protocol/security claims can never be overwritten,
  and a veto fires **before** the token's `jti` is recorded — a denied token leaves no
  trace.

(Pre-login and pre-registration points are natural extensions of the same machinery.)

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

## Fail-closed by default

If a hook can't be run — an in-process action throws, or an external endpoint times out /
errors / returns non-2xx — the operation is **denied**. A security control that fails open
is not a control. Set `external_actions.fail_open` to `true` only for enrichment-only hooks
where availability matters more than the control, accepting that a downed endpoint then
issues tokens without the enrichment.

## Honest scope

- **`TokenMinting` is the only wired hook in v1.** The pipeline is generic; other points
  are additive.
- **The external call is on the token hot path.** Keep the endpoint fast — the timeout is
  short (default 3s) and there is **no retry** (a hook is synchronous, not a webhook).
- **A hook cannot rewrite protocol claims.** `iss`, `sub`, `exp`, `scope`, `aud`, `cnf`,
  `ent`, … are protected; enrichment only adds non-reserved keys.
- **This is a primitive, not a policy.** What a hook decides is the host's logic; the
  platform guarantees the mechanics — deny-by-default, fail-closed, signed, SSRF-guarded,
  audited.

## Where to go next

- [Add a token claims hook](../cookbook/add-a-token-hook.md) — the recipe.
- [Custom hook action](../extension-points/custom-action.md) — the contract in detail.
- [Security: external actions](../security/external-actions.md) — the threat model.
