---
title: Sign a CLI in with the device grant
weight: 41
description: The package serves the two protocol endpoints; the verification page a person approves on is yours. Here is the page.
---

# Sign a CLI in with the device grant

RFC 8628 exists for a program with no browser of its own — a CLI, a CI job, a container,
a TV. It prints a short code, the person approves it on whatever device is already in
their hand, and the program polls until tokens arrive.

**This package serves the two machine endpoints** — `POST /oauth/device_authorization`
and the `device_code` grant at `/oauth/token` — and **not the page the person approves
on**. That page needs your session, your layout and your idea of who is signed in, which
is exactly the boundary every other browser-facing surface here sits on. It is about
forty lines.

## What the CLI does (no host code)

```http
POST /oauth/device_authorization
Content-Type: application/x-www-form-urlencoded

client_id=cid_…&scope=openid%20profile%20email%20offline_access
```

```json
{
  "device_code": "…",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://id.example.com/device",
  "verification_uri_complete": "https://id.example.com/device?user_code=WDJB-MJHT",
  "expires_in": 600,
  "interval": 5
}
```

`verification_uri` is `{issuer}/device`. **That path is a promise your host has to keep** —
the package puts it in the response and in discovery, and nothing checks that you serve
it. Route your verification page there.

The scopes are a ceiling, not a request: a device authorization naming a scope the client
is not registered for is refused with `invalid_scope` rather than quietly reduced. There
is no browser in front of it to notice a smaller grant, so silence would surface much
later as a claim that never arrived.

## The page you write

Three calls on {@see \Cbox\Id\OAuthServer\Contracts\DeviceAuthorization}:

```php
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;

// 1. Resolve the code to the app and scopes — so the person sees what they are
//    approving BEFORE they approve it.
$pending = $devices->pending($userCode);   // null when unknown or expired

// 2. They said yes. Binds the request to this user (and the organization they are
//    acting for, if your product has them).
$devices->approve($userCode, $user->id, $organizationId);

// 3. Or no.
$devices->deny($userCode);
```

Four things this page has to get right, each of which has bitten a real deployment:

**Resolve the code from the link, do not just prefill it.** `verification_uri_complete`
exists so the person does not have to type or confirm anything — following the link *is*
that step. A page that fills the field in and then waits for a Continue click reads, on a
phone, as something having gone wrong.

**Never `autocomplete="one-time-code"` on the input.** That attribute means "a code
delivered out of band *to this device*" — an SMS or authenticator OTP — and Safari, iOS
and every password manager will offer the last such code they saw, silently replacing the
one the link prefilled. The form then submits a code the person never saw and the page
blames a device that did nothing wrong. Use `autocomplete="off"`.

**Rate-limit the lookup per signed-in user.** A user code is short by design because a
person types it. Without a limit, one authenticated session can enumerate the space.

**Re-check on approve.** A code can expire between the lookup and the click, so
`approve()` returning false is an ordinary outcome to render, not an exception.

## Polling, from the CLI's side

```http
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=…&client_id=cid_…
```

| Answer | Meaning |
|---|---|
| `authorization_pending` | Not finished. Poll again at `interval`. |
| `slow_down` | Too fast. Add 5s to the interval — permanently, not for one round. |
| `access_denied` | They said no. Stop. |
| `expired_token` | The code aged out. Stop, and offer to start again. |

The `@cboxdk/id-js` and `id-go` SDKs implement that loop, including the back-off.

## Related

- [Approve agent actions with CIBA](approve-agent-actions-with-ciba.md) — the same shape
  when the person and the program are *not* at the same keyboard.
- [Integrating existing apps](integrating-existing-apps.md).
