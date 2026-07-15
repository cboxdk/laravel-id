---
title: Custom hook action
description: The Action / ActionTransport contracts — write an in-process handler or swap how external hooks are called
weight: 41
---

# Custom hook action

[Inline hooks](../core-concepts/external-actions.md) are built on small contracts you
can implement.

## Write an in-process action

Implement `Cbox\Id\ExternalActions\Contracts\Action` and list it in config. It runs
synchronously at its hook point:

```php
interface Action
{
    public function handle(ActionContext $context): ActionResult;
}
```

- `ActionContext::string($key)` reads the point's payload (for `token_minting`:
  `client_id`, `subject`, `user_id`, `organization_id`, `grant`, plus `scopes`/`claims`).
- Return `ActionResult::continue([...])` to allow (optionally with enrichment) or
  `ActionResult::deny($reason)` to veto.
- Actions are resolved from the container, so constructor-inject whatever you need.
- Registration is deny-by-default: only classes listed in
  `cbox-id.external_actions.hooks.<point>` run.

## Swap how external endpoints are called

The transport that makes the outbound HTTP call is behind
`Cbox\Id\ExternalActions\Contracts\ActionTransport`:

```php
interface ActionTransport
{
    public function send(ExternalActionEndpoint $endpoint, ActionContext $context): ActionResult;
}
```

The default `HttpActionTransport` is SSRF-guarded, signed, short-timeout, no-retry and
fails closed. Rebind it to change transport behaviour (a different signing scheme, mTLS,
a message-queue bridge) while keeping the pipeline and fail-closed semantics:

```php
$this->app->singleton(ActionTransport::class, MyMtlsActionTransport::class);
```

If you rebind it, preserve the guarantees callers rely on: **fail closed** on any error
(unless `fail_open`), **never follow redirects**, keep TLS verification on, and return a
deny — never throw — on failure.

## Test with the shipped fake

`Cbox\Id\ExternalActions\Testing\InteractsWithExternalActions` gives you
`fakeActionTransport()` (an in-memory transport you script with `willEnrich()` /
`willDeny()` and assert with `assertSent()`), so the pipeline and your hook are testable
without touching the network.

See [Security: external actions](../security/external-actions.md) for the invariants.
