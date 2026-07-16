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

```
CBXLIC1.<base64url(claims)>.<base64url(ed25519-signature)>
```

The token is an **Ed25519** (libsodium) detached signature over its own claims — a vetted
primitive, algorithm fixed (no `alg` field to confuse). The app verifies it against a
**bundled public key**, with no network call, checking the signature, `nbf`/`exp` (with a
small clock skew), and an optional domain binding. Any failure is treated as unlicensed
and logged; it never throws into a request.

## Configuration

```dotenv
CBOX_ID_LICENSE_KEY=CBXLIC1.…          # the customer's key
CBOX_ID_LICENSE_PUBLIC_KEY=…           # base64 Ed25519 public key (safe to ship)
CBOX_ID_LICENSE_DOMAIN=id.acme.com     # optional; defaults to the issuer host
```

Generate a keypair once:

```bash
php artisan id:license:keygen
```

The **public** key is baked into the app (safe to ship — it can only verify). The
**secret** key lives only in the issuer (the billing service) that mints keys; it never
ships. The framework contains the verifier and the token format (`LicenseSigner` /
`Ed25519LicenseVerifier`); the issuer supplies the private key and the plan→license
business logic.

## What a license carries

License id, customer, optional deployment/domain binding, plan, a map of **entitlement
grants** (`{"feature.sso": {"enabled": true}, "limits.orgs": {"limit": 100}}`), and
issued-at / not-before / expiry. Grants are data, so a new paid feature is a new
entitlement key — no verifier change.

> **Not copy-protection.** The app is source-available; a determined actor can patch out
> the check. The key is the honest default gate and the licensing boundary, not DRM.
