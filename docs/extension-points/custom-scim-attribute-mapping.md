---
title: Custom SCIM attribute mapping
description: Control how platform user attributes map onto the SCIM User schema a downstream app receives
weight: 4
---

# Custom SCIM attribute mapping

Each provisioning connection carries an `attribute_mapping` that decides how a
platform user's attributes are rendered into the SCIM 2.0 `User` resource pushed to
the downstream app. A mapping entry is `scimPath => sourceKey`: the value at
`sourceKey` in the platform snapshot is written to the SCIM attribute `scimPath`.

## The default

When a connection's mapping is empty, `Cbox\Id\Provisioning\Support\AttributeMapping::DEFAULTS`
applies — the attributes every SCIM app expects:

```php
[
    'userName'       => 'email',
    'displayName'    => 'name',
    'name.formatted' => 'name',
    'emails'         => 'email',
]
```

`active` is never mapped from source data; it is set by the lifecycle operation
itself (create/update → true, deactivate → false).

## Supplying your own

Pass a mapping at registration. Dot-notation targets a SCIM sub-attribute; the
`emails` target is expanded to the RFC 7643 multi-valued form
`[{value, primary: true, type: work}]`:

```php
app(ProvisioningConnections::class)->register(
    // …
    attributeMapping: [
        'userName'         => 'email',
        'name.givenName'   => 'first_name',
        'name.familyName'  => 'last_name',
        'displayName'      => 'name',
        'emails'           => 'email',
    ],
);
```

The `sourceKey`s must exist in the platform snapshot. The framework's snapshot is
built from the `Subject` value object (`email`, `name`); a host with richer user
data binds its own `Cbox\Id\Identity\Contracts\Subjects` resolver so those keys are
present in the snapshot.

## Enterprise extension

An inline `enterprise` source value is emitted under the RFC 7643 §4.3 Enterprise
User extension URN, with the extension URN added to the resource's `schemas`:

```php
// source snapshot: ['email' => …, 'enterprise' => ['department' => 'Engineering']]
// →
[
    'schemas' => [
        'urn:ietf:params:scim:schemas:core:2.0:User',
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
    ],
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User' => ['department' => 'Engineering'],
    // …
]
```

## Deeper control

For behaviour the mapping table can't express (computed values, per-app quirks in
how PATCH bodies are framed), rebind the `Cbox\Id\Provisioning\Contracts\ScimClient`
contract with your own decorator over `HttpScimClient`, or bind a different
`ProvisioningService` — both are resolved from the container, contracts-first.
