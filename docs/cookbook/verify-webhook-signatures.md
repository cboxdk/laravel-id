---
title: Verify webhook signatures
weight: 46
description: Choose how an endpoint's webhooks are signed — the Cbox scheme or Standard Webhooks — and verify deliveries on the receiving side, in PHP or with any Standard Webhooks library.
---

# Verify webhook signatures

Every webhook delivery is signed with HMAC-SHA256 and the endpoint's secret. Each endpoint
picks one of two signature schemes:

- **Cbox** — the default, and the only scheme before 1.23. Every existing endpoint stays on
  it, and its wire format has not changed.
- **Standard Webhooks** — the [Standard Webhooks](https://www.standardwebhooks.com/)
  specification. Any Standard Webhooks library, in any language, verifies these deliveries
  without code written for this package.

The body is the same JSON envelope on both. Only the signature headers differ.

## Which scheme to choose

| | Cbox | Standard Webhooks |
|---|---|---|
| Use it when | the receiver already verifies `X-Cbox-Signature`, or uses a Cbox ID SDK | the receiver uses a Standard Webhooks library, or a language with no Cbox ID SDK, or a platform that verifies Standard Webhooks itself |
| Secret | 64 hex characters | `whsec_` + base64 of 32 random bytes |
| HMAC key | the secret string, as written | the base64-decoded bytes after `whsec_` |
| Signed string | `{timestamp}.{body}` | `{webhook-id}.{timestamp}.{body}` |
| Signature encoding | lowercase hex | base64 |
| Idempotency key in a header | no (use the body's `delivery_id`) | `webhook-id` |

For a new integration with nothing already built, choose Standard Webhooks. The message id
is signed and sent as a header, so a receiver can dedupe a delivery before it parses the
body.

## What goes on the wire

Each delivery carries **only its own scheme's headers**, plus `Content-Type:
application/json`. A Standard Webhooks delivery has no `X-Cbox-*` headers, and a Cbox
delivery has no `webhook-*` headers. Each receiver verifies exactly one scheme. Sending both
would add noise, and receivers would have to be told which set to ignore.

**Cbox**

```
X-Cbox-Timestamp: 1700000000
X-Cbox-Signature: t=1700000000,v1=<hex HMAC-SHA256 of "1700000000.<raw body>">
```

**Standard Webhooks**

```
webhook-id: 01HF3QK9Z8VN0T7M2XW5RB4YCD
webhook-timestamp: 1700000000
webhook-signature: v1,<base64 HMAC-SHA256 of "01HF3QK9Z8VN0T7M2XW5RB4YCD.1700000000.<raw body>">
```

- `webhook-id` is the **delivery id**, the same value as the envelope's `delivery_id`. It
  stays the same on every retry of that delivery, so it is the idempotency key. Each
  endpoint gets its own delivery, so two endpoints receiving the same event see different
  ids.
- The timestamp is **when this attempt was sent**, not when the event happened. A retry is
  signed again with a new timestamp, so it passes the receiver's tolerance window, while a
  captured old attempt does not.
- `webhook-signature` is a space-delimited list. Today it carries one `v1,` entry, because
  an endpoint has one secret at a time. Verify every entry the spec allows: the helper below
  and the Standard Webhooks libraries already do.

The envelope is `{"type", "sequence", "data", "delivery_id"}` on both schemes. The
specification also *recommends* a top-level `timestamp` for when the event happened. This
envelope does not carry one. That field is not part of the signature, and no Standard
Webhooks verifier depends on it.

## Register an endpoint on Standard Webhooks

Registration through `WebhookRegistry` is unchanged and always uses the Cbox scheme. To
choose the scheme, use `WebhookSigningSchemes`:

```php
use Cbox\Id\Webhooks\Contracts\WebhookSigningSchemes;
use Cbox\Id\Webhooks\Enums\SignatureScheme;

$registered = app(WebhookSigningSchemes::class)->registerWithScheme(
    $organizationId,
    'https://app.example.com/webhooks/cbox-id',
    ['membership.created', 'user.updated'],
    SignatureScheme::StandardWebhooks,
);

$registered->secret;            // "whsec_…" — shown once; hand it to the receiver
$registered->signatureScheme(); // SignatureScheme::StandardWebhooks
```

`registerForEnvironmentWithScheme($url, $eventTypes, $scheme)` is the platform-wide variant.
Like `registerForEnvironment()`, it is for operator callers only.

## Move an existing endpoint

```php
$endpoint = app(WebhookSigningSchemes::class)->changeSignatureScheme(
    $endpointId,
    $organizationId,               // null for an environment-wide endpoint
    SignatureScheme::StandardWebhooks,
);                                 // null if this owner has no such endpoint
```

The change applies to the next attempt. A delivery that is still pending, or is waiting
for a retry, is signed under the scheme the endpoint has **when it is sent**.

**No new secret is minted, and the secret is not shown again.** The receiver keeps the
secret it already has:

- **Cbox → Standard Webhooks:** the hex secret becomes `'whsec_'.base64_encode($hexSecret)`.
  The conversion is lossless. The decoded key is exactly the 64 bytes the Cbox scheme
  already signed with, and 64 bytes is within the spec's 24–64 byte range.
  `StandardWebhookSignature::secretFor($hexSecret)` does the conversion.
- **Standard Webhooks → Cbox:** the `whsec_…` string itself is the Cbox key, as written.
  Pass it to a Cbox verifier unchanged.

Move the receiver to the new verifier before you switch the endpoint. Otherwise its
deliveries fail verification until the receiver is updated. Those deliveries are retried,
not lost.

## Verify in PHP

The package ships both receiver halves. Each one throws `InvalidWebhookSignature` with a
stable `$reason`, and returns nothing when the delivery verifies.

```php
use Cbox\Id\Webhooks\Exceptions\InvalidWebhookSignature;
use Cbox\Id\Webhooks\Support\StandardWebhookSignature;
use Illuminate\Http\Request;

public function __invoke(Request $request)
{
    try {
        StandardWebhookSignature::verify(
            $request->getContent(),        // the RAW body, never re-encoded JSON
            $request->headers->all(),      // names matched case-insensitively
            config('services.cbox_id.webhook_secret'), // "whsec_…"
            // tolerance: 300 seconds by default, in both directions
        );
    } catch (InvalidWebhookSignature $e) {
        logger()->warning('webhook refused', ['reason' => $e->reason]);

        return response('', 400);
    }

    // At-least-once delivery: dedupe on webhook-id before acting.
    $id = $request->header('webhook-id');
    if (! cache()->add("cbox-id-webhook:{$id}", true, now()->addDay())) {
        return response('', 200); // already handled
    }

    $event = $request->json()->all(); // type, sequence, data, delivery_id
    // …

    return response('', 200);
}
```

For a Cbox-scheme endpoint, the same code uses `CboxWebhookSignature::verify()` with the hex
secret:

```php
use Cbox\Id\Webhooks\Support\CboxWebhookSignature;

CboxWebhookSignature::verify($request->getContent(), $request->headers->all(), $hexSecret);
```

| `$e->reason` | Meaning |
|---|---|
| `missing_header` | A required header is absent or empty. |
| `invalid_timestamp` | The timestamp is not a positive integer of unix seconds. |
| `timestamp_too_old` / `timestamp_too_new` | Outside the tolerance window. A clock off by minutes shows up here. |
| `invalid_secret` | The secret is unusable. A Standard Webhooks secret must start with `whsec_`. If you pasted the hex secret, convert it with `secretFor()`. |
| `malformed_signature` | The signature header cannot be parsed. |
| `unsupported_version` | No `v1` signature is present. |
| `signature_mismatch` | Wrong secret, or the body, id or timestamp changed after signing. A framework or proxy that rewrites the body causes this. |

Refuse the request whatever the reason. Answer with a 4xx, and the delivery is retried.

Unlike the reference libraries, `StandardWebhookSignature::verify()` **requires** the
`whsec_` prefix. A hex secret is also valid base64, so an unprefixed secret would quietly
key the HMAC with the wrong bytes. Every delivery would then fail as a mismatch, with no
hint why.

## Verify in other languages

Any Standard Webhooks library verifies these deliveries with the `whsec_` secret exactly as
it was shown. The specification repository maintains libraries for JavaScript/TypeScript,
Python, Go, Rust, Java, Ruby, PHP, C# and Elixir:

```javascript
import { Webhook } from "standardwebhooks";

const wh = new Webhook(process.env.CBOX_ID_WEBHOOK_SECRET); // "whsec_…"
wh.verify(rawBody, headers); // throws if the delivery does not verify
```

```python
from standardwebhooks.webhooks import Webhook

wh = Webhook(os.environ["CBOX_ID_WEBHOOK_SECRET"])  # "whsec_…"
wh.verify(raw_body, headers)
```

Pass the raw body bytes the request arrived with. Most frameworks have a raw-body option
for webhook routes.

## How it is tested

- The Standard Webhooks signer and verifier are held to the specification's own published
  vector: secret `whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw`, id `msg_p5jXN8AQM9LWM0D4loKWxJek`,
  timestamp `1614265330`, body `{"test": 2432232314}` →
  `v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=`. That vector is in
  `tests/Fixtures/Webhooks/standard-webhooks.json`, next to a converted-hex-secret vector
  computed independently with OpenSSL.
- Delivery tests capture the real outgoing request and verify it with the helper. They also
  check that a retry keeps its `webhook-id` and gets a fresh timestamp, that switching
  schemes changes the headers, and that a tampered body or timestamp fails.
- The Cbox verifier is held to the cross-SDK fixture
  `tests/Fixtures/Webhooks/signature.json`, the same file the Cbox ID SDKs verify against.

## Not yet

- **Secret rotation with an overlap window.** An endpoint has one secret, so the header
  carries one signature. `StandardWebhookSignature::sign()` already accepts several secrets
  and emits one `v1,` entry for each, and both verifiers accept a list. Rotation itself is
  not built yet.
- **Asymmetric `v1a` (ed25519) signatures.** Not sent. Verifiers skip `v1a` entries.
