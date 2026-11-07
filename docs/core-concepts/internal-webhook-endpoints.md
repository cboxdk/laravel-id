---
title: Operator-pinned internal webhook receivers
description: Configure explicit private webhook destinations without weakening public URL validation.
weight: 45
---

# Operator-pinned internal webhook receivers

Public customer URLs retain the shared SSRF policy. For a receiver the operator owns
on a private network, configure `cbox-id.webhooks.trusted_endpoints` as an exact HTTPS
URL → IP map. The map is server configuration, never a tenant API setting. No wildcard,
URL credentials, query or fragment is allowed. Each request is pinned to that address;
redirects and proxies are disabled and the connected peer is verified. TLS hostname and
certificate verification remain enabled. The cURL transport is required for this path.

```php
'trusted_endpoints' => [
    'https://signals.internal/cbox-id/webhooks' => '10.42.5.20',
],
```

Authorize only the precise receiving path. Other paths on the same hostname still go
through the normal public-address guard. Replace pins when the internal address changes
and test delivery before removing the old deployment. A failed pin is a failed delivery;
it does not fall back to an unverified connection. Keep `verify_url` enabled.
