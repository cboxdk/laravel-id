---
title: CIBA
description: Threat model for OpenID Connect CIBA (poll mode) — hashed single-use auth_req_id, poll throttle, split identifiers, deny-by-default user resolution
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
| Deny-by-default | unresolvable `login_hint` never creates a request (`unknown_user_id`) | `CibaAuthenticationService::request()` |
| Environment scope | `BelongsToEnvironment` — cross-env invisible | `Models\BackchannelAuthRequest` |

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

## Single-use under concurrency

`redeem()` re-reads the request `lockForUpdate()` inside a transaction and re-checks
`status === 'approved'` before minting, then flips it to `redeemed`. Two concurrent
polls on a leaked `auth_req_id` cannot both observe `approved` and each mint a
token. The pending/slow-down `last_polled_at` writes are committed **outside** that
transaction, so a rolled-back mint can never leave the client able to poll
unthrottled.

## Honest limits

- **Poll mode only.** `ping`/`push` delivery (a client notification endpoint) is not
  implemented; discovery advertises `backchannel_token_delivery_modes_supported:
  ["poll"]`. Poll mode needs no client callback and avoids that attack surface
  entirely.
- **The approval channel is the host's to secure.** CIBA decouples approval to a
  second device, but the OP mints the token the moment `approve()` is called — the
  strength of the notification and the device (is it phishing-resistant? is the
  `binding_message` actually shown?) is the host's responsibility.
- **`login_hint` is an enumeration signal to trusted clients.** Returning
  `unknown_user_id` distinguishes a known from an unknown user, but only to a client
  that already passed client authentication. That is the CIBA-spec behavior and the
  trade is bounded to trusted clients.
- **This is a primitive.** Whether a given action warrants a CIBA approval, and what
  the approval prompt says, is the host's policy; the package enforces the grant
  mechanics.
