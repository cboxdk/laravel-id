---
title: Rich authorization requests
description: RFC 9396 authorization_details on token exchange — a person's token narrowed to one action, with registered types only and the original login carried forward
weight: 16
---

# Security: rich authorization requests (RFC 9396)

A client that holds a person's access token can exchange it (RFC 8693) for a token that
names exactly one action in `authorization_details`: one deployment plan, one payment.
The resource server checks that the token approves the action it is asked to do, so a
token minted for one plan cannot approve another.

```http
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<the person's access token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&resource=https://engine.example.com
&authorization_details=[{"type":"cbox_infra_change","plan_digest":"sha256:…"}]
```

The response echoes `authorization_details` (§7), and the access token carries them as
a claim (§9.1).

## Controls

| Control | Mechanism | Where |
| --- | --- | --- |
| Registered types only | every entry's `type` must be in the client's `authorization_details_types` (§10); null = none, so no existing client changes | `Client::allowsAuthorizationDetailsType()`, `TokenExchangeService` |
| Bounded shape | a JSON array of 1–10 objects, each with a string `type`; values are strings, numbers, booleans, arrays and objects only, at most four deep, 4 KB in all | `AuthorizationDetails::fromRequest()` |
| Same person, same client | the exchange's usual rules hold: an active subject token issued to (or naming) the caller, down-scope only, DPoP continuity, never an acted token | `TokenExchangeService` |
| No newer login than the real one | the new token carries the subject token's own `auth_time` and `acr` (RFC 9470), never fresh ones, so a resource server can still demand a recent or two-factor login | `JwtTokenIssuer::issueForExchange()` |
| Not forgeable by a hook | `authorization_details` is a reserved claim; a `TokenMinting` hook cannot add, change or strip it | `JwtTokenIssuer::RESERVED_CLAIMS` |
| Refused loudly | anything malformed or unregistered is `400 invalid_authorization_details` (§5) | `TokenController` |

## What it does not prove

The exchange proves that the client held a live token of this person and asked for this
action. It does not prove that the person saw the action. When that matters (an agent
acting for someone), use CIBA, where the person approves the binding message on their
own device. When the person is in the client's own browser, the client obtains a fresh
token for them with an authorization-code redirect, with `max_age` and `acr_values` for
step-up (RFC 9470), and exchanges that token immediately.

## Registering a client

An operator sets the types on the client:

```php
$client->forceFill(['authorization_details_types' => ['cbox_infra_change']])->save();
```
