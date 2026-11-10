---
title: CIBA
description: Threat model for OpenID Connect CIBA (poll and ping mode) — hashed single-use auth_req_id, poll throttle, split identifiers, deny-by-default user resolution
weight: 15
---

# Security: CIBA

CIBA (`Cbox\Id\OAuthServer\` — `BackchannelAuthentication`) issues tokens on the
strength of an out-of-band human approval, so its controls are load-bearing. The
polling state machine is the device-authorization grant's, and inherits its
hardening.

## Controls

| Control | Mechanism | Where |
| --- | --- | --- |
| Hashed at rest | `auth_req_id` stored only as SHA-256; looked up by hash + client id | `CibaAuthenticationService`, `ciba_requests.auth_req_id_hash` (unique) |
| Single-use | approved → redeemed flip under `lockForUpdate` in a transaction | `CibaAuthenticationService::redeem()` |
| TTL | short approval window; `requested_expiry` clamped to the configured ceiling | config `oauth.ciba.ttl_seconds` |
| Poll throttle | polling faster than `interval` → `slow_down`, clock not advanced | `CibaAuthenticationService::redeem()`, config `oauth.ciba.poll_interval` |
| Split identifiers | client's `auth_req_id` ≠ host's internal approval id | `BackchannelAuthenticationResult` |
| Deny-by-default | unresolvable `login_hint` never creates a request (`unknown_user_id`); an email hint must be one the person **confirmed**, and an unconfirmed one answers exactly like an unknown one | `CibaAuthenticationService::request()` |
| Bound audience | RFC 8707 `resource` on the backchannel request is checked before anyone is prompted, stored with the request, and the poll may repeat it but never name another (`invalid_target`) | `BackchannelAuthenticationController`, `TokenController::ciba()`, `ciba_requests.resource` |
| Prompt flooding | per client + `login_hint` (5 per 60 s) and per person across every client (10 per 600 s) → `429 slow_down` with `Retry-After`; nothing is filed, nobody is prompted | config `oauth.ciba.rate_limits.*` |
| Audit | `oauth.ciba.requested` (actor: the client), `oauth.ciba.approved` / `oauth.ciba.denied` (actor: the person) | `CibaAuthenticationService` |
| Bound approval | a CIBA token carries `auth_req_id` (the client's own, raw: spent at that point) and `binding_message` (exactly what the person saw), on the access token and the ID Token; read from the locked row; reserved, so no `TokenMinting` hook can forge them; never on a refresh | `BackchannelBinding`, `CibaAuthenticationService::redeem()`, `JwtTokenIssuer` |
| Ping delivery | operator-registered https endpoint only; `client_notification_token` required (≤ 1024 chars); token and raw `auth_req_id` encrypted at rest and cleared once delivered or redeemed; SSRF guard with pinned DNS, no redirects; queued with short timeouts and retries | `QueuedCibaClientNotifications`, `Jobs\NotifyCibaClient`, config `oauth.ciba.ping.*` |
| Environment scope | `BelongsToEnvironment` — cross-env invisible | `Models\BackchannelAuthRequest` |

## Self-registered agents and CLIs

A client that registered itself (RFC 7591, `mcp` mode) may use CIBA, and the device
grant, only where a protected resource opened them to such clients:

```php
'protected_resources' => [[
    'identifier' => 'https://app.example.com/mcp',
    'scopes' => ['mcp:read', 'mcp:write'],
    'dynamic_clients' => true,
    'dynamic_client_grants' => ['ciba', 'device_code'],
    // 'dynamic_public_backchannel' => true,   // see below
]],
```

Such a client is anyone who reached the registration endpoint, so every request is
checked again, against the one resource it names (`DynamicGrantPolicy`):

- `resource` is **required** and must be a resource that opened the grant
  (`invalid_target` otherwise);
- a `binding_message` is **required** (`invalid_binding_message`). The client shows it in
  its own window, the person sees the same words beside Approve; a short code at its end
  is the convention;
- the rate limits above apply as to every client.

**Register with your own key.** The recommended shape is
`token_endpoint_auth_method: "private_key_jwt"` with an inline `jwks`: the server hands
out no secret, each install proves possession of a key only it holds, and the client is
confidential — CIBA's usual requirement.

**Public clients, deliberately.** CIBA normally refuses public clients: a `client_id` is
not a secret, and without client authentication anyone could spray prompts at
`login_hint`s. A resource may still allow it with `dynamic_public_backchannel`, for a CLI
that cannot keep a key. That is acceptable here because what makes the flow safe does not
depend on who the client is: the person sees the client's name, the resource, the scopes
and the binding message, and the request is rate limited per client, per hint and per
person. What a public client loses is attribution — two installs of the same CLI are
indistinguishable — so prefer `private_key_jwt` wherever a key can be kept.

**`backchannel_user_code_parameter` is not supported**, and is advertised as `false`.
CIBA's `user_code` is a secret the person sets up with the OP beforehand and hands to the
client; it is not a code the client shows. The matching code a CLI shows belongs in the
`binding_message`.

## The two-identifier split

CIBA has two parties who must not be conflated:

- The **client** (the agent) holds `auth_req_id` — its polling secret, returned by
  the backchannel endpoint and presented at the token endpoint.
- The **host's approval surface** holds the internal request id — the handle to
  `approve()` / `deny()`, delivered only via the
  `oauth.backchannel_authentication_requested` domain event.

The backchannel endpoint returns **only** `auth_req_id` (never the internal id), so
a client can never approve its own request. Keeping them separate is the structural
guard behind the whole flow.

## Bound tokens

A resource server that asked a person to approve ONE thing (a deployment plan) must be
able to tell that a token is that approval, not another one the same client holds. A
token minted from a CIBA request carries:

| Claim | Value |
| --- | --- |
| `auth_req_id` | the client's own `auth_req_id` for the request |
| `binding_message` | the binding message the person saw; absent when none was sent |

Both are on the access token and, when `openid` was granted, the ID Token. A client that
put a digest (or a prefix of one) in the binding message, and stored its `auth_req_id`,
can check both. The `auth_req_id` is the raw value: redemption is single-use, so by the
time a token carries it, it opens nothing. A refresh does not carry the binding on.

The binding reaches the access token through `AuthenticationEvent` and
`AuthenticationAwareTokenIssuer`; a host's own issuer that does not implement that
contract mints tokens without it.

## Ping mode

Poll is the default and every existing client stays on it. An operator registers ping
for a client:

```php
app(ClientRegistry::class)->configureBackchannelTokenDelivery(
    $client, BackchannelTokenDeliveryMode::Ping, 'https://app.example.com/webhooks/cbox-id/ciba',
);
```

The backchannel request must then carry `client_notification_token` (`invalid_request`
otherwise, before anyone is prompted). When the person approves or denies, a queued job
POSTs to the endpoint:

```http
POST /webhooks/cbox-id/ciba
Authorization: Bearer <client_notification_token>
Content-Type: application/json

{"auth_req_id": "auth_req_…"}
```

Any 2xx is delivered (`oauth.ciba.notified`). 5xx, 408, 429 and connection failures are
retried (2 s, 5 s, 15 s, 30 s; `oauth.ciba.ping.max_attempts`, default 5); anything else,
or the last failure, is `oauth.ciba.notification_failed`. The client then calls the token
endpoint once with the `auth_req_id`, and may still poll if a ping never arrives.
Dynamic registration cannot set ping.

## Single-use under concurrency

`redeem()` re-reads the request `lockForUpdate()` inside a transaction and re-checks
`status === 'approved'` before minting, then flips it to `redeemed`. Two concurrent
polls on a leaked `auth_req_id` cannot both observe `approved` and each mint a
token. The pending/slow-down `last_polled_at` writes are committed **outside** that
transaction, so a rolled-back mint can never leave the client able to poll
unthrottled.

## Honest limits

- **Poll and ping, no push.** Discovery advertises `backchannel_token_delivery_modes_supported:
  ["poll", "ping"]`. Push (the token in the callback) is not implemented: ping hands the
  client only an already-spent-on-redeem handle, never a credential.
- **The approval channel is the host's to secure.** CIBA decouples approval to a
  second device, but the OP mints the token the moment `approve()` is called — the
  strength of the notification and the device (is it phishing-resistant? is the
  `binding_message` actually shown?) is the host's responsibility.
- **`login_hint` is an enumeration signal.** Returning `unknown_user_id` distinguishes a
  known from an unknown user. For a confidential client that is the CIBA-spec behavior;
  a self-registered public client (only where a resource allowed it) sees it too, bounded
  by the per-client-and-hint rate limit.
- **This is a primitive.** Whether a given action warrants a CIBA approval, and what
  the approval prompt says, is the host's policy; the package enforces the grant
  mechanics.
