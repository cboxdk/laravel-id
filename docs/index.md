---
title: Cbox ID
description: Documentation for the self-hostable, Laravel-native identity platform
weight: 1
---

# Cbox ID

`cboxdk/laravel-id` is a self-hostable, Laravel-native identity platform — the framework
behind central login, enterprise SSO, directory sync, RBAC, billing-driven entitlements and a
tamper-evident audit trail. It is UI-free and interface-driven: every capability sits behind a
contract you can bind, mock, extend or replace.

Security is the core value proposition. A breach of an identity platform exposes thousands of
customers at once, so the design is deny-by-default throughout, and every module is verified
(tests + PHPStan level max + `composer audit`) before it ships.

## How it's built

The package is one Composer package with clean internal module boundaries. Two layers:

- **Kernels** (`Cbox\Id\Kernel\*`) — shared primitives that depend only on the framework
  (plus, in dependency order, each other). Tenancy, Crypto, Audit, Events, Authorization.
- **Domain modules** (`Cbox\Id\*`) — features built on the kernels. Organization, Identity,
  AccessControl, Directory, Federation, Webhooks, AuditQuery.

Products don't embed this package — they authenticate against the running instance over OIDC
and call it via the SDK. The framework is embedded only in the hosted app.

> **Don't want to build the app layer yourself?** There's a full, deployable
> application built on this framework — the **Cbox ID app** — with the admin console,
> hosted login, onboarding and app-layer add-ons already implemented. See its
> [operator docs](../../../host/docs/index.md). This documentation covers the
> framework you'd build on directly; the app is the batteries-included path.

## Module reference

| Module | Primary contracts | What it does |
|---|---|---|
| `Kernel\Tenancy` | `TenantContext` | Deny-by-default org isolation; `runAs`, `scopedTo` (hierarchy roll-up), `withoutScope`. |
| `Kernel\Crypto` | `KeyManager`, `TokenSigner`, `SecretBox` | Signing keys + JWKS + rotation; alg-allowlisted JWTs; AEAD envelope encryption. |
| `Kernel\Audit` | `AuditLog` | Append-only, hash-chained trail; signed checkpoints. |
| `Kernel\Events` | `EventBus` | Transactional outbox; at-least-once relay. |
| `Kernel\Authorization` | `PolicyDecisionPoint`, `RelationshipStore`, `EntitlementReader`/`EntitlementWriter` | Owned ReBAC engine, deny-by-default PDP, billing-fed entitlement projection. |
| `Organization` | `Organizations`, `OrganizationHierarchy`, `Memberships` | Tenants, closure-tree hierarchy (reseller/parent), memberships. |
| `Identity` | `UserDirectory`, `SessionManager` | Global users, federated identities, sessions, password auth. |
| `AccessControl` | `Roles`, `AccessChecker` | RBAC with hierarchy-aware roll-down. |
| `Directory` | `Directories`, `DirectorySync` | SCIM provisioning; deprovision revokes sessions immediately. |
| `Federation` | `Connections`, `FederationFlow`, `AssertionValidator` | Per-org SSO connections + login orchestration. |
| `Webhooks` | `WebhookRegistry`, `WebhookDispatcher` | HMAC-signed delivery + retries; fans out `EventDelivered`. |
| `AuditQuery` | `AuditReader` | Filtered/paginated reads + SIEM pull-stream. |

## Sections

### New to this?

- [Start here — the mental model](start-here.md) — what a central IdP is, the five things you actually decide, and why, in one page

### Getting started

- [Installation](getting-started/installation.md)
- [Quickstart](getting-started/quickstart.md) — from empty app to a federated login in a few calls

### Understand it

- [Architecture & patterns](architecture.md) — kernels vs domain, contracts-first DI, dogfooding
- [Security](security.md) — the invariants, tenant isolation, tamper-evident audit
- [Standards & conformance](standards.md) — every RFC/spec implemented, and to what extent
- [FAPI hardening](fapi.md) — the enforceable FAPI 2.0 baseline for high-assurance clients
- [Compliance mapping](compliance.md) — how controls map to SOC 2, ISO 27001, NIS2, GDPR, HIPAA, PCI-DSS
- [Threat model](threat-model.md) — STRIDE analysis and mitigations

### Do things

- [Cookbook](cookbook.md) — central login, reseller hierarchy, billing entitlements, SCIM, SSO, webhooks
- [Authorization & the decision plane](authorization.md) — live permission + entitlement decisions (`/oauth/decisions`), the hot path, and the token hybrid
- [Entitlements & billing](entitlements-and-billing.md) — keep your own billing engine, push entitlements so every product enforces the same plan

### Make it yours

- [Integrating an existing app](integrating-existing-apps.md) — adopt over existing users/auth (incl. Laravel Passport), unify auth across products
- [Extending & customizing](extending.md) — swap any contract; implement a SAML/OIDC validator
- [Testing](testing.md) — the shippable `InteractsWith*` helpers and fakes
