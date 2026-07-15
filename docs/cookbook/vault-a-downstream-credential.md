---
title: Vault a downstream credential
description: Store a third-party API key sealed, authorize an agent, and lease it for a single call
weight: 40
---

# Vault a downstream credential

Give an AI agent access to a downstream credential (say an OpenAI key) without ever
handing it the long-lived secret. Everything runs inside an
[environment](../core-concepts/environments.md).

## 1. Store the credential (sealed)

```php
use Cbox\Id\TokenVault\Contracts\SecretVault;

$secret = app(SecretVault::class)->store(
    name: 'openai-prod',
    provider: 'openai',
    secret: $openAiApiKey,           // sealed at rest via SecretBox; not kept in plaintext
    ownerType: 'organization',       // optional scoping metadata
    ownerId: $organizationId,
);
```

## 2. Authorize an agent

Grant one OAuth client (the agent) access, capping how long it may hold a leased
value:

```php
app(SecretVault::class)->grant(
    secretId: $secret->id,
    clientId: 'agent-7',             // the agent's OAuth client_id
    maxTtlSeconds: 60,               // shortens the vault default; never extends it
);
```

No grant means no lease — the vault is deny-by-default.

## 3. Lease it for a call

When the agent needs to call OpenAI, lease the value for immediate use:

```php
$lease = app(SecretVault::class)->lease($secret->id, clientId: 'agent-7', purpose: 'summarize-ticket');

$response = Http::withToken($lease->secret)->post('https://api.openai.com/v1/…');

// $lease->expiresAt is the advisory window — stop using and drop the value by then.
```

The lease and its purpose are audited (`vault.secret.leased`); the value itself is
never logged or persisted unsealed.

## Rotate and revoke

```php
$vault = app(SecretVault::class);

$vault->rotate($secret->id, $newApiKey);   // re-seals under the same row-bound context
$vault->revokeGrant($secret->id, 'agent-7'); // this agent can no longer lease
$vault->revoke($secret->id);               // no one can lease again
```

## Gate a high-risk lease on a human

For a sensitive credential, require a fresh [CIBA](../core-concepts/ciba.md)
approval before leasing: run the CIBA flow, and only call `lease()` once the request
is approved. The vault exposes the mechanics; your app decides the policy.

See [AI token vault](../core-concepts/token-vault.md) and
[Security: token vault](../security/token-vault.md).
