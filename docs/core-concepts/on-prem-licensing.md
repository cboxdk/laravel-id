---
title: On-prem licensing
description: How a signed, offline-verifiable license key unlocks paid entitlements on a self-hosted install — through the same entitlement gate billing feeds.
weight: 15
---

# On-prem licensing

The framework is free to self-host. Paid / enterprise capabilities are unlocked by a
**signed license key** that a self-hosted install verifies **offline** and projects into
the [entitlement gate](entitlements-and-billing.md) — the same gate the online billing
projection feeds. No license (or an invalid one) means the free tier, deny-by-default.

## The two feeders, one gate

- **Online / SaaS:** billing pushes per-org entitlements via the `EntitlementWriter`
  (source `billing`).
- **On-prem:** a license key grants entitlements **deployment-wide** (the whole install
  is licensed, not one org). The verifier overlays them onto the `EntitlementReader`
  (source `license`).

Either way, feature code just asks the entitlement reader — it never knows which feeder
answered.

## How a key is verified

Verification uses the shared, framework-agnostic [`cboxdk/license`](https://github.com/cboxdk/license)
core — the same package the issuer mints with, so the format can never drift. A token is
an **Ed25519** (EdDSA) signed artifact, algorithm pinned (no `alg` confusion). The app
verifies it against a **bundled public key**, with no network call, checking the
signature, validity window (with a small clock skew and an optional **grace** period past
expiry), the **deployment** binding, and an optional **domain** binding. Any failure
resolves to unlicensed (deny-by-default) with a logged reason; it never throws into a
request. `LicensingServiceProvider` maps the verified result's entitlements + limits onto
the entitlement reader.

## Configuration

```dotenv
CBOX_ID_LICENSE_KEY=…                  # the customer's key
CBOX_ID_LICENSE_PUBLIC_KEY=…           # base64 Ed25519 public key (safe to ship)
CBOX_ID_LICENSE_DEPLOYMENT_ID=…        # this install's id; must match the key's binding
CBOX_ID_LICENSE_DOMAIN=id.acme.com     # optional; defaults to the issuer host
CBOX_ID_LICENSE_GRACE=0                # optional seconds of post-expiry grace
```

Generate a keypair once:

```bash
php artisan id:license:keygen
```

The **public** key is baked into the app (safe to ship — it can only verify). The
**secret** key lives only in the issuer (the billing service) that mints keys; it never
ships. The verifier and the token format live in `cboxdk/license`; the issuer supplies the
private key and the plan→license business logic.

## What a license carries

License id, customer, optional deployment/domain binding, plan, a map of **entitlement
grants** (`{"feature.sso": {"enabled": true}, "limits.orgs": {"limit": 100}}`), and
issued-at / not-before / expiry. Grants are data, so a new paid feature is a new
entitlement key — no verifier change.

> **Not copy-protection.** The app is source-available; a determined actor can patch out
> the check. The key is the honest default gate and the licensing boundary, not DRM.
