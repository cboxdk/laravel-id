---
title: Require a person's approval for one action
description: Hold a sensitive change until the person behind a key or token approves it on their device, then spend the approval exactly once
weight: 42
---

# Require a person's approval for one action

A management key or an agent's delegated token can be allowed to do more than its owner
wants it to do unsupervised: mint keys, rotate a client secret, delete an environment.
`ActionApprovals` holds such a change until the person approves it, on the same approval
surface as a [CIBA](approve-agent-actions-with-ciba.md) sign-in request, and lets your host
run it exactly once.

What the package provides:

- a pending request bound to a **digest of exactly that action**;
- approval and denial through `BackchannelAuthentication::approve()` / `deny()`, bound to
  the person it was raised for;
- `consume()`, which is true once, only for that digest, only before it lapses.

What stays yours: deciding which actions need approval, notifying the person, and holding
the caller while they decide.

## 1. Ask

Hash what is being approved: the action, its target and its input, canonicalised. Then
file the request under your own first-party client:

```php
use Cbox\Id\OAuthServer\Contracts\ActionApprovals;

$digest = hash('sha256', json_encode(['apps.secret.rotate', $appId, $input]));

$approval = app(ActionApprovals::class)->request(
    $stepUpClient,                 // your host's own first-party client
    $ownerSubjectId,               // the person who must approve
    'deploy-bot wants to rotate the secret of Billing · K7Q2',
    $digest,
    ttlSeconds: 300,               // 30–900
);

// Answer the caller: "pending, poll $approval->requestId".
```

The binding message is what the person sees beside Approve, so name the actor, the action
and the target, and end with a short code the caller also shows. It must be 1–255
characters. The digest must be a lowercase hex SHA-256.

## 2. Notify

The package raises `oauth.backchannel_authentication_requested` with
`purpose: action`, exactly as for a CIBA request. Push to the person's device from your
listener; the approval surface you built for CIBA lists and answers these too.

## 3. Run it once

When the caller comes back with the request id, recompute the digest from the request
it is making now and spend the approval:

```php
if (! app(ActionApprovals::class)->consume($requestId, $digest)) {
    // Not approved, denied, lapsed, already spent, or approved for something else.
}

// Run the action.
```

`status($requestId)` answers `pending`, `approved`, `denied`, `expired` or `consumed` for
the caller's polling.

## What it guarantees

- An approval for one action cannot run another: the digest must match.
- It runs once: `consume()` flips it to consumed in the same statement that checks it.
- Only the person it was raised for can approve it.
- It is never a token: the token endpoint treats an action approval's handle as unknown,
  whichever client presents it.
