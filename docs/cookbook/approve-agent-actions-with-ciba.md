---
title: Approve agent actions with CIBA
description: Wire the host notification + approval surface to the CIBA backchannel domain event
weight: 41
---

# Approve agent actions with CIBA

[CIBA](../core-concepts/ciba.md) ships the protocol; the **notification and approval
surface are yours**. Here is how to wire them.

## 1. The agent initiates (no host code)

The agent calls the backchannel endpoint directly:

```http
POST /oauth/backchannel_authentication
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

scope=openid&login_hint=alice@example.com&binding_message=Approve%20deployment%20to%20prod
```

```json
{ "auth_req_id": "auth_req_…", "expires_in": 300, "interval": 5 }
```

## 2. Notify the user on the emitted event

The OP emits `oauth.backchannel_authentication_requested` when the request is
created. Domain events are delivered through the outbox as an `EventDelivered`
Laravel event (see [architecture](../core-concepts/architecture.md)); listen for it
and notify the user's authentication device. The payload carries the **internal**
request id (your approval handle) — never the client's `auth_req_id`:

```php
use Cbox\Id\Kernel\Events\EventDelivered;
use Illuminate\Support\Facades\Event;

Event::listen(EventDelivered::class, function (EventDelivered $delivered): void {
    if ($delivered->event->type !== 'oauth.backchannel_authentication_requested') {
        return;
    }

    $payload = $delivered->event->payload;

    // Show $payload['binding_message'] to the user, and keep $payload['request_id']
    // as the handle to approve/deny.
    Notification::route(/* the user's device */)->notify(
        new ApproveAgentRequest($payload['request_id'], $payload['binding_message']),
    );
});
```

## 3. Record the user's decision

When the user taps approve or deny on their device, call the contract with the
**internal request id**:

```php
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;

app(BackchannelAuthentication::class)->approve($requestId, $organizationId);
// or
app(BackchannelAuthentication::class)->deny($requestId);
```

## 4. The agent polls and gets its token

The agent polls `/oauth/token` with `grant_type=urn:openid:params:grant-type:ciba`
and the `auth_req_id`, receiving `authorization_pending` until approval, then an
`access_token` and `id_token` bound to the approving user.

Show the `binding_message` verbatim on the approval screen so the user knows exactly
what they are authorizing. See [Security: CIBA](../security/ciba.md).
