---
title: Hook points
description: Every inline-hook point — when it fires, the payload it sends, whether a deny stops anything, and what an unreachable endpoint means there
weight: 39
---

# Hook points

An [inline hook](../core-concepts/external-actions.md) is the platform pausing mid-flow
to ask your code a question. This page is the reference for **where** it pauses: six
points, each with a payload shape you can rely on, a defined meaning for "deny", and a
defined meaning for "your endpoint did not answer".

Everything below applies equally to in-process actions
([`Action`](custom-action.md)) and registered HTTPS endpoints — same points, same
payloads, same decisions.

## The points

| Hook point | Fires | Deny means | Unreachable means | Enrichment |
|---|---|---|---|---|
| `token_minting` | just before an access token is signed, on every grant | no token is issued, and no `jti` is recorded | **deny** | adds claims |
| `post_login` | after authentication succeeds, before the session row is written | no session is created; the login fails | **allow** | ignored |
| `pre_registration` | before a subject is created | no account is created | **deny** | ignored |
| `post_registration` | immediately after, with the new subject id | *nothing* — audited only | allow | ignored |
| `pre_password_change` | before a credential is written | the password is not changed | **deny** | ignored |
| `post_password_change` | immediately after | *nothing* — audited only | allow | ignored |

A `post_*` point cannot veto. The operation has already committed and the hook has no way
to unmake it, so the pipeline audits the deny (`external_action.denied`, with
`vetoable: false`) and then reports an allow. A deny you cannot act on is worse than no
deny at all, and enforcing that in one place beats trusting six call sites to remember it.

## Payloads

Each point has one typed payload value object under
`Cbox\Id\ExternalActions\Payloads\`. That class — not a call site assembling an array —
defines the wire shape, so a change to it is a visible edit to a value object. Keys are
snake_case, and a key that does not apply is present and `null` rather than missing.

The HTTP body is always `{"context": {"hook": "<point>", …payload}}`.

### `token_minting` — `TokenMintingPayload`

```json
{
  "hook": "token_minting",
  "client_id": "cli_01H…",
  "subject": "usr_01H…",
  "user_id": "usr_01H…",
  "organization_id": "org_01H…",
  "scopes": ["openid", "profile"],
  "grant": "user",
  "claims": { "iss": "…", "sub": "…", "scope": "…" }
}
```

`grant` is `"user"` or `"client_credentials"`. **There is no separate
credentials-exchange hook point** — a machine-to-machine grant is this one, with
`user_id` null and `grant` set accordingly. Filter on it.

`claims` is the fully-assembled base token, read-only. Reply with
`{"action":"continue","claims":{…}}` to add claims; reserved protocol and security claims
(`iss`, `sub`, `exp`, `aud`, `cnf`, `scope`, `roles`, `permissions`, …) are never
overwritten.

### `post_login` — `LoginPayload`

```json
{
  "hook": "post_login",
  "user_id": "usr_01H…",
  "organization_id": "org_01H…",
  "amr": ["pwd", "mfa"],
  "ip": "203.0.113.7",
  "user_agent": "Mozilla/5.0 …"
}
```

`amr` is how the user authenticated — `pwd`, `mfa`, `sso`, `magic_link`, … — which makes
"SSO logins skip the check, password logins do not" expressible without any other lookup.

The hook fires from `SessionManager::start()`, the one primitive every login path funnels
through, so it covers magic links, SSO and a host's own password form without any of them
knowing about it. Enrichment is ignored: this point decides, it does not decorate. Add
claims at `token_minting`, which is the point that owns them.

### `pre_registration` / `post_registration` — `RegistrationPayload`

```json
{
  "hook": "pre_registration",
  "user_id": null,
  "email": "sam@acme.test",
  "name": "Sam",
  "has_password": true
}
```

`user_id` is null before the account exists and set afterwards. `has_password` is the
difference between a self-serve signup and a just-in-time provision from SSO, directory
sync or an invitation.

### `pre_password_change` / `post_password_change` — `PasswordChangePayload`

```json
{ "hook": "pre_password_change", "user_id": "usr_01H…" }
```

The subject, and nothing else. **The password never crosses the wire** — no plaintext, no
hash, no derivative. A hook is an outbound call to a customer-controlled URL, and no
password rule is worth putting credential material on it. A check that genuinely needs the
secret (a corporate dictionary, a breach corpus) belongs in an in-process `Action` or
behind `BreachedPasswordCheck`, both of which run in the app's own memory.

Not fired by `Subjects::storeCredential()` — the bulk-import path carries a credential
that was set in the system you are migrating *from*, and firing per row would mean one
blocking HTTP call per imported user.

## Fail policy

"Deny" and "did not answer" are different questions. A hook that answers deny always
denies, at every point, and no setting changes that. A hook that could not be **consulted**
— timeout, connection refused, non-2xx, unparseable reply, or an in-process action that
threw — answers to the point's fail policy:

- **Fail closed** (`token_minting`, `pre_registration`, `pre_password_change`) — each
  guards a write that is hard to undo, so an unanswered gate must not read as permission.
  The blast radius is bounded: a failed grant is retried, and registrations and password
  changes are low-volume and user-initiated.
- **Fail open** (`post_login`) — the hottest path in the product, with the worst failure
  mode. Failing closed here means one customer's endpoint outage locks *every* one of
  their users out of *every* application, the admin console they would use to pause the
  hook included. Some logins going unexamined during an outage is recoverable; a total
  lockout may not be.
- **Fail open** (`post_registration`, `post_password_change`) — there is no decision to
  fail closed to.

Override it. Per point wins over the global switch, which wins over the default:

```php
// config/cbox-id.php
'external_actions' => [
    // Unset by default, so each point's own default applies. A bool here applies to
    // every point: false closes them all, true opens them all.
    'fail_open' => env('CBOX_ID_ACTIONS_FAIL_OPEN'),

    'fail_policy' => [
        // "We would rather block a login than admit an unexamined one."
        'post_login' => 'closed',
    ],
],
```

An unrecognised value is treated as "not configured" and falls back to the point's own
default, so a typo can never quietly open a gate.

## Cost

Hooks are synchronous and on auth paths, so the module is built to charge nothing when you
are not using them:

- **No endpoints registered → no query and no call.** The active endpoint set is cached per
  (environment, hook point); registering, pausing or removing an endpoint invalidates it
  immediately, so the TTL is a backstop. An environment with no hooks pays a cache read.
- **Several endpoints → one timeout, not N.** A fan-out is issued concurrently, so a second
  or third endpoint does not add its own `connect_timeout + timeout` to every login. Note
  the semantic consequence: every endpoint is called before any reply is read, so a hook
  can observe an operation another hook vetoed. The decision is unchanged — the first deny
  in registration order still wins.
- **Keep the endpoint fast.** Default budget is 2s connect + 3s read, with **no retry**.

## Scoping

`token_minting` and `post_login` carry an `organization_id`, so a tenant's own endpoints
fire for their own users, alongside the environment's. The registration and
password-change points carry no organization — those operations do not have one — so only
environment-level endpoints (`organization_id` null) fire for them. A tenant's endpoint
never sees another tenant's payload at any point.

## Registering

```php
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;

$registered = app(ExternalActions::class)->register(
    HookPoint::PreRegistration,
    'https://hooks.acme.com/signup-gate',
);

// $registered->secret — reveal-once HMAC secret; verify X-Cbox-Signature with it.
```

Or in-process, which needs no network at all:

```php
// config/cbox-id.php
'external_actions' => [
    'hooks' => [
        'pre_registration' => [App\Actions\AllowlistedDomainsOnly::class],
    ],
],
```

```php
final class AllowlistedDomainsOnly implements Action
{
    public function handle(ActionContext $context): ActionResult
    {
        $email = $context->string('email') ?? '';

        return str_ends_with($email, '@acme.test')
            ? ActionResult::continue()
            : ActionResult::deny('domain is not on the allowlist');
    }
}
```

## Testing

`InteractsWithExternalActions` swaps the HTTP transport for an in-memory fake and rebuilds
the singletons that hold the pipeline, so no network is involved:

```php
$transport = $this->fakeActionTransport()->willDeny('device is not enrolled');
$this->registerActionEndpoint(HookPoint::PostLogin, 'https://risk.example.test');

expect(fn () => app(SessionManager::class)->start('usr_1', 'org_1', ['pwd']))
    ->toThrow(ActionDenied::class);
```

## Where to go next

- [External actions & inline hooks](../core-concepts/external-actions.md) — the model.
- [Custom hook action](custom-action.md) — the `Action` / `ActionTransport` contracts.
- [Security: external actions](../security/external-actions.md) — the threat model.
