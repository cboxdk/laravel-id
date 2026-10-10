---
title: Pipes (connected accounts)
description: Let people connect their own GitHub, Google, Slack or Salesforce account so your app can call that API on their behalf, with the tokens stored in the token vault and refreshed for you
weight: 12
---

# Pipes (connected accounts)

Pipes (`Cbox\Id\Pipes\`) let a signed-in person connect **their own account** at a
third-party service — GitHub, Google, Microsoft 365, Slack, Salesforce, HubSpot, Linear,
Notion — so that your app can call that service's API on their behalf. The platform runs
the OAuth 2.0 authorization code flow with PKCE, keeps the access and refresh tokens
**sealed in the [token vault](token-vault.md)**, refreshes them before they expire, and
hands a fresh access token to an app you have authorised when it asks.

Your app never stores a third-party token. It asks for one when it needs to make a call.

## Mental model

| Thing | What it is | Where it lives |
|---|---|---|
| **Provider** | A catalogue entry: endpoints, default scopes, how tokens refresh, expire and are revoked | `PipeProviderCatalog` (code, the same for everyone) |
| **Pipe** | One environment's OAuth app at one provider: its client id, its **sealed** client secret, the scopes to ask for, and which of your apps may lease tokens | `Models\Pipe`, `Models\PipeGrant` |
| **Connection** | One person's connected account at one pipe, bound to (environment, user, pipe) | `Models\PipeConnection` — the tokens themselves are user-owned vault secrets |

Three contracts:

- **`Contracts\Pipes`** — configure, update, remove a pipe; grant and revoke apps.
- **`Contracts\PipeConnections`** — the connect flow (`start` → `complete`), a person's
  list, and `disconnect`.
- **`Contracts\PipeTokens`** — `lease` a fresh access token for an app, and `refresh`.

## The provider catalogue

| Key | Provider | Default scopes | Expiry and refresh | Revocation on disconnect |
|---|---|---|---|---|
| `github` | GitHub | `read:user` | OAuth App tokens do not expire; GitHub App user tokens expire after 8 h and refresh | `DELETE /applications/{client_id}/grant` |
| `google` | Google | `openid email profile` | 1 h, refresh (`access_type=offline`, `prompt=consent`) | RFC 7009, with the refresh token |
| `microsoft` | Microsoft 365 | `offline_access User.Read` | ~1 h, refresh; tenant parameter (default `common`) | none — Microsoft has no revocation endpoint |
| `slack` | Slack | `users:read` (as `user_scope`) | 12 h when token rotation is on, refresh; long-lived otherwise | `auth.revoke` |
| `salesforce` | Salesforce | `api refresh_token` | no `expires_in`; 2 h assumed (the default session policy); domain parameter | RFC 7009, with the refresh token |
| `hubspot` | HubSpot | `oauth crm.objects.contacts.read` | 30 min, refresh | `DELETE /oauth/v1/refresh-tokens/{token}` |
| `linear` | Linear | `read` | expires, refresh | `POST /oauth/revoke` |
| `notion` | Notion | — (pages chosen by the person) | no `expires_in`; a rotating refresh token is kept | `POST /v1/oauth/revoke` (JSON, `Notion-Version` header) |

GitHub's endpoints and the vendor names shared with the
[sign-in catalogue](sign-in-provider-catalogue.md) are read from it rather than restated.
A pipe is still a separate OAuth client from a sign-in connection: it asks for API scopes
and keeps a refresh token, which a sign-in never does.

Per-installation values (Microsoft's `tenant`, Salesforce's login `domain`) are
**parameters** with a default and a strict pattern, because they are substituted into an
endpoint the client secret is sent to.

## Configure a pipe

```php
use Cbox\Id\Pipes\Contracts\Pipes;

$pipe = app(Pipes::class)->configure(
    provider: 'github',
    clientId: 'Iv1.8a61f9b3a7aba766',
    clientSecret: $secretFromGitHub,      // sealed at rest, never returned
    scopes: ['read:user', 'repo'],        // null = the catalogue's defaults
);

// Which of your apps may lease the tokens people connect through it.
app(Pipes::class)->grant($pipe->id, clientId: 'cid_01j9…');
```

## Connect a person's account

Your app owns the browser. Start the flow for the person who is signed in, keep the
returned state in **their** session, redirect, and finish on the callback:

```php
use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\ValueObjects\PipeConnectState;

// GET /account/pipes/github/connect
$authorization = app(PipeConnections::class)->start('github', $user->id, route('pipes.callback', 'github'));
session()->put('pipes:github', $authorization->state->toArray());

return redirect()->away($authorization->url);

// GET /account/pipes/github/callback?code=…&state=…
$flow = PipeConnectState::fromMixed(session()->pull('pipes:github'));
$connection = app(PipeConnections::class)->complete($flow, $request->string('state'), $request->string('code'));
```

`complete()` checks the state in constant time, exchanges the code with the PKCE verifier
only that session holds, and writes the connection for the person and pipe recorded at
**start**, whatever the callback request says. A failure is a `PipeConnectFailed` with a
stable `reason`: `state_mismatch`, `pipe_unavailable` or `exchange_failed`. Connecting
again replaces the tokens in place, which is how a `needs_reauth` connection becomes
`active` again.

## Lease a token

```php
use Cbox\Id\Pipes\Contracts\PipeTokens;

$token = app(PipeTokens::class)->lease('github', $userId, clientId: 'cid_01j9…', purpose: 'list-repos');

Http::withToken($token->accessToken)->get('https://api.github.com/user/repos');
```

`lease()` refreshes first when the access token expires within
`pipes.lease_refresh_skew_seconds` (60 s). The answers, in order:

| Outcome | Exception | Meaning |
|---|---|---|
| refused | `PipeLeaseDenied` | the app is not granted this pipe, or there is no such (enabled) pipe. Uniform; the reason is audited, never returned |
| not connected | `PipeConnectionMissing` | the app is granted, the person has not connected. Show a Connect button |
| reconnect | `PipeReauthorizationRequired` | the connection is `needs_reauth`. Send the person through Connect again |
| try again | `PipeRefreshFailed` | a needed refresh could not complete right now (provider down, another refresh in progress) |
| a token | `PipeAccessToken` | `accessToken`, `expiresAt` (the provider's), `leaseExpiresAt` (the vault's advisory window), `scopes`, `metadata` |

`metadata` carries the non-secret parts of the token response an app needs to call the
API at all — Salesforce's `instance_url`, Slack's `team.id`, Notion's `workspace_id`.

## Refresh

`cbox-id:pipes:refresh` runs every five minutes from the scheduler (`pipes.schedule`) and
refreshes every active connection whose access token expires within
`pipes.refresh_ahead_seconds` (10 min). The sweep is latency, not correctness: a lease
refreshes on its own when it has to.

A refresh is **single-flight**. A refresh token is one-shot at every provider that rotates
them, and spending it twice can revoke the whole grant. A refresh first claims the
connection with one atomic `UPDATE` on `refresh_claimed_until`; whoever wins refreshes, a
lease that loses waits up to `pipes.refresh_wait_milliseconds` and then uses what the
winner stored, and the sweep that loses moves on. A claim held by a process that died
lapses after `pipes.refresh_claim_seconds`.

When the provider refuses the refresh token (`invalid_grant`, Slack's
`invalid_refresh_token`, HubSpot's `BAD_REFRESH_TOKEN`, GitHub's `bad_refresh_token`), or
the token expired with nothing to refresh it with, the connection becomes
**`needs_reauth`** and `pipe.connection.needs_reauth` is emitted. An outage (a 5xx, a 429,
a timeout) or a refusal of the *client* (`invalid_client`) is transient: the connection
stays `active`, `refresh_failures` and `last_error` record it, and the next attempt may
succeed.

## Disconnect

`disconnect()` revokes at the provider where it can (see the catalogue table), revokes
both tokens in the vault, deletes the connection and emits `pipe.connection.disconnected`
with `revoked_at_provider`. Revoking at the provider is best effort; forgetting the tokens
here is not.

## Events

| Event | When |
|---|---|
| `pipe.connection.connected` | a person connected or reconnected |
| `pipe.connection.needs_reauth` | the connection stopped working; the person must reconnect |
| `pipe.connection.disconnected` | the connection was removed |

Payloads name the connection, user and provider — never a token. See the
[webhook event reference](../reference/webhook-events.md).

## Testing

`Testing\InteractsWithPipes` runs the real flow with only the provider faked:

```php
uses(InteractsWithPipes::class);

$pipe = $this->configurePipe('github');
$this->grantPipe($pipe, 'cid_app');
$this->connectPipeAccount('github', 'user_1', ['access_token' => 'gho_test']);

expect($this->leasePipeToken('github', 'user_1', 'cid_app')->accessToken)->toBe('gho_test');
```

## Where to go next

- [Connect a person's third-party account](../cookbook/connect-a-third-party-account.md) — the recipe end to end.
- [Security: Pipes](../security/pipes.md) — what protects the tokens, and the honest limits.
- [AI token vault](token-vault.md) — the store every pipe token lives in.
