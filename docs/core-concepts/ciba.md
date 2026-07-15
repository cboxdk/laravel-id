---
title: CIBA backchannel approval
description: OpenID Connect Client-Initiated Backchannel Authentication (poll mode) — human-in-the-loop approval for autonomous / AI agent actions
weight: 12
---

# CIBA backchannel approval

CIBA (OpenID Connect **Client-Initiated Backchannel Authentication**) is the
human-in-the-loop approval grant for autonomous / AI agents. An agent asks to act;
a human approves out-of-band on their own device; only then does the agent get a
token. It lives in the OAuth server (`Cbox\Id\OAuthServer\`) as a new grant and
endpoint, and is modelled on the device-authorization flow.

This package ships the **protocol** — the backchannel endpoint, the request store,
the poll grant, and `approve()` / `deny()`. The **user notification and the
approval UI are the host's** (exactly as the interactive OAuth consent screen is):
the package emits a domain event the host listens for.

## The flow (poll mode)

```
 agent (client)                 cbox-id (OP)                 host app        user
      │  POST /oauth/backchannel_authentication              │               │
      │   client auth + login_hint + binding_message ──────► │               │
      │  ◄──── { auth_req_id, expires_in, interval }          │               │
      │                                    emits event ─────► │  notify ────► │
      │                                                       │  ◄── approve  │
      │  POST /oauth/token (grant_type=…:ciba, auth_req_id)   │               │
      │   ──► authorization_pending / slow_down …             │               │
      │  ──► once approved: { access_token, id_token }        │               │
```

1. **Initiate.** The agent calls `POST /oauth/backchannel_authentication`
   (client-authenticated) with a `login_hint` naming the user, an optional
   `binding_message`, and `scope`. The OP resolves the user, stores a pending
   request, and returns `auth_req_id` + `interval`. It emits
   `oauth.backchannel_authentication_requested` (payload: the internal request id,
   client id, user id, binding message, scopes).
2. **Notify + approve.** The host listens for that event, notifies the user's
   authentication device, and on their decision calls
   `BackchannelAuthentication::approve($requestId)` or `deny($requestId)` — using the
   **internal** request id from the event, never the client's `auth_req_id`.
3. **Poll.** The agent polls `POST /oauth/token` with
   `grant_type=urn:openid:params:grant-type:ciba` and the `auth_req_id`. It gets
   `authorization_pending` (and `slow_down` if it polls too fast) until approval,
   then an `access_token` **and an `id_token`** bound to the approving user.

## Security properties

Mirrors the device grant's hardening:

- **Hashed at rest, single-use.** `auth_req_id` is a CSPRNG secret stored only as a
  SHA-256 hash and looked up by hash + client id; a redeemed request is spent and can
  never mint again (flip to `redeemed` under a row lock, so concurrent polls can't
  double-mint).
- **TTL + poll throttle.** A short approval window; polling faster than `interval`
  returns `slow_down` without advancing the clock (the throttle write commits even
  when the mint transaction rolls back).
- **Two separate identifiers.** The client's polling secret (`auth_req_id`) and the
  host's approval handle (internal request id) are distinct — the client can never
  approve its own request.
- **Deny-by-default user resolution.** An unresolvable `login_hint` never creates a
  request (`unknown_user_id`). The endpoint is client-authenticated, so this signal
  reaches only trusted clients.
- **Environment-owned.** A request in one environment is invisible to any other.

## Honest scope

- **Poll mode only.** The `ping` and `push` delivery modes (a client notification
  endpoint) are not implemented; discovery advertises `["poll"]`. Poll mode needs no
  client-side callback and is the simplest to secure.
- **The approval channel's strength is the host's.** CIBA decouples approval to a
  second device, but whether that device and its notification are phishing-resistant
  is the host's responsibility — the OP issues the token once `approve()` is called.
- **Binding message is advisory.** `binding_message` lets the user tie the approval
  prompt to the agent's request; the host must actually show it.

## Where to go next

- [Approve agent actions with CIBA](../cookbook/approve-agent-actions-with-ciba.md) —
  wire the notification + approval surface to the domain event.
- [AI token vault](token-vault.md) — the credential half of agent authority.
- [Security: CIBA](../security/ciba.md) — the threat model.
