---
title: Add a token claims hook
description: Enrich access tokens with a custom claim, or veto issuance, via an inline hook
weight: 43
---

# Add a token claims hook

Add a custom claim to every access token — or block issuance — with a
[`TokenMinting` inline hook](../core-concepts/external-actions.md). Two ways.

## In-process (a class in your app)

Write an `Action` and register it:

```php
use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;

final class AddTenantTier implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        $orgId = $context->string('organization_id');

        if ($orgId !== null && $this->overQuota($orgId)) {
            return ActionResult::deny('organization is over quota'); // → token endpoint returns access_denied
        }

        return ActionResult::continue(['tenant_tier' => $this->tierFor($orgId)]); // adds a claim
    }
}
```
```php
// config/cbox-id.php
'external_actions' => [
    'hooks' => [
        'token_minting' => [App\Actions\AddTenantTier::class],
    ],
],
```

The claim appears on the access token:
```json
{ "iss": "cbox-id", "sub": "…", "scope": "openid", "tenant_tier": "pro" }
```
Reserved claims (`sub`, `exp`, `scope`, `aud`, …) can't be overwritten — only new keys land.

## External HTTP endpoint

Point the hook at your own HTTPS service instead:

```php
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;

$registered = app(ExternalActions::class)->register(HookPoint::TokenMinting, 'https://hooks.acme.com/token');
// Store $registered->secret — shown once — to verify X-Cbox-Signature on your endpoint.
```

Your endpoint receives a signed POST `{"context": {...}}` and replies within a few seconds:
```json
{ "action": "continue", "claims": { "tenant_tier": "pro" } }
// or: { "action": "deny", "reason": "organization is over quota" }
```

Verify the signature before trusting the request:
```php
$expected = hash_hmac('sha256', $request->header('X-Cbox-Timestamp').'.'.$request->getContent(), $secret);
// compare (constant-time) against the v1=… part of X-Cbox-Signature, and reject stale timestamps.
```

## Fail-closed

If your hook is unreachable or errors, issuance is **denied** by default (a control that
fails open is not a control). For an enrichment-only hook where you'd rather issue without the
claim than block, set `external_actions.fail_open` to `true`. See
[Security: external actions](../security/external-actions.md).
