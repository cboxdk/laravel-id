---
name: cboxdk-package
description: >-
  Engineering standards for cboxdk Laravel packages. Use whenever building,
  reviewing, documenting, or scaffolding any cboxdk/laravel-* package (framework
  library or full application package). Covers naming & identity, module
  architecture, contracts-first DI, thin controllers, dogfooded testing traits,
  the /docs structure, license + CycloneDX SBOM compliance, queue-autoscale and
  laravel-telemetry usage, the honest-crypto stance, and the pre-commit
  verification gate. Invoke it before writing code so new work matches the rest
  of the ecosystem.
---

# cboxdk package standards

The single source of truth for how every `cboxdk/*` Laravel package is built.
Apply these unless a package's own `CLAUDE.md` overrides a specific point. When in
doubt, match the existing sibling packages.

## 1. Identity & naming

- **Company name is "Cbox"** in all prose, docblocks, copyright, and UI — never
  "Cbox ApS", never "cbox.dk" as a product name. The legal entity name does not
  appear in code or docs.
- **GitHub org / Composer vendor:** `cboxdk`. **PHP namespace:** `Cbox\<Package>\`
  (e.g. `Cbox\Id\`, `Cbox\Telemetry\`).
- **Package name prefix:** `laravel-<name>` for anything that depends on Laravel
  (`cboxdk/laravel-id`, `cboxdk/laravel-telemetry`); framework-agnostic libraries
  drop the `laravel-` prefix.
- **PHP:** require `^8.4`; develop and CI on 8.4 **and** 8.5. Never use a feature
  unavailable in 8.4.
- Everything ships as a package first. Local dev workspaces stay out of git; every
  publishable package lives in its own repo under `cboxdk`.

## 2. Two package tiers

- **Framework library** (e.g. `laravel-id`): dependency-light. Only vetted,
  pinned primitives. **No UI, no telemetry runtime, no queue-autoscale coupling** —
  a library must not force those on its host. Expose contracts and let the host
  wire infrastructure.
- **Full / application package** (SaaS apps, first-party products): compose the
  libraries and **do** adopt the shared infrastructure:
  - `cboxdk/laravel-telemetry` for observability (own the telemetry — no
    OpenTelemetry-graveyard external coupling).
  - `cboxdk/laravel-queue-autoscale` for queue workers; size workers by depth,
    don't hand-tune.
  Full packages dogfood these the same way libraries dogfood their own testing
  traits.

## 3. Architecture

- **Kernels vs domain modules.** Cross-cutting concerns (crypto, events, audit,
  tenancy, authorization) are kernels other modules build on; domain modules
  depend on kernels, never the reverse. One package, clear internal module
  boundaries — not a pile of micro-packages.
- **Contracts-first DI.** Every capability is an interface (`Contracts\*`) bound to
  an implementation in the module's service provider and resolved from the
  container. Depend on the interface, never the concrete class. This is what makes
  fakes and host overrides possible.
- **Deny-by-default.** Tenant isolation, authorization, and protocol validators
  reject anything not explicitly allowed. A type/route/scope with no registered
  handler is refused, never silently trusted.
- **Configurable models.** Where a host may want to extend a model, resolve the
  class through config (`config('<pkg>.models.user')`) so they can subclass it; the
  package still owns the schema.

## 4. Thin controllers

Controllers do HTTP, nothing else:

1. Resolve/validate input (Form Request or inline validation).
2. Delegate to a **contract** (service) resolved from the container.
3. Map the result to a response (or a mapper/resource class).

No business logic, no queries, no crypto, no orchestration in a controller. If a
controller method is more than a few lines, the logic belongs in a service. The
same rule applies to jobs, commands, and listeners — they are thin adapters over
domain services.

## 5. Dogfooding & testing

- **Every module ships `Testing/InteractsWith*` traits and fakes** (e.g.
  `FakeEventBus`, `FakeAuditLog`, `FakeWebAuthnVerifier`) — and **the package's own
  tests use them**. If a fake is awkward to use in your own suite, fix the fake.
- **Pest** for tests. Compose the `InteractsWith*` traits in the base `TestCase`.
- **Test against real vectors.** Crypto/protocol code is proven against genuine
  inputs (RFC test vectors, real signed assertions from a software authenticator,
  real keypairs) — never against a mock that just returns success.
- Fixtures that PHPStan must see (trait composition sites) live under
  `tests/Fixtures` and are included in the analysis paths.

## 6. The verification gate (run before every commit)

A module is only committed when **all** of these are green. Never stamp a module
done on a partial run.

```
vendor/bin/pint --test
vendor/bin/phpstan analyse --no-progress --memory-limit=1G   # larastan, level max
vendor/bin/pest
composer audit --no-dev
composer license-check
composer sbom && git diff --exit-code sbom.json              # SBOM not stale
```

- **PHPStan level max** with larastan. Fix the underlying cause — no
  `@phpstan-ignore`, no baseline, no `assert()`/inline-`@var` to override
  inference, no casts-to-silence, no widening types just to pass.
- **Pint** with the project style; run `--dirty` while iterating, `--test` in CI.
- Wire all of the above into `.github/workflows/ci.yml` on the 8.4/8.5 matrix.

## 7. Honest-crypto & conformance stance

- **Never hand-roll cryptography or protocol verification.** Wrap a vetted,
  maintained library (firebase/php-jwt, onelogin/php-saml, robrichards/xmlseclibs,
  spomky-labs/cbor-php, libsodium). OpenSSL/sodium primitives are fine; bespoke
  COSE/CBOR/XML-DSig/JWT parsing is not.
- **Pin algorithms.** Verify against an allow-list (e.g. RS256-pinned keys) to
  close algorithm-confusion / `alg:none`.
- **Never label unverified conformance "production-ready."** If signature/protocol
  conformance is not tested against real vectors, say so and isolate it behind a
  contract with a refusing default until it is.

## 8. Supply chain: licenses & SBOM

Ship these two `bin/` scripts (self-contained, no plugins/network) and wire them
into `composer.json` scripts + CI:

- **`bin/check-licenses.php`** — fails the build if any dependency in
  `composer.lock` is not offered under a permissive license (MIT, BSD-*,
  Apache-2.0, ISC, 0BSD, …). Handle **SPDX dual-licensing** correctly: a package
  passes if **any** of its listed licenses is permissive (e.g. nette's
  `BSD-3-Clause OR GPL-3.0-only` passes on BSD). Real exceptions are listed inline
  with a justification.
- **`bin/generate-sbom.php`** — emits a **deterministic CycloneDX 1.5** `sbom.json`
  straight from `composer.lock` (sorted components, content-derived serial number),
  so the committed SBOM only changes when dependencies do. CI regenerates it and
  fails on drift.

`composer.json` scripts: `license-check`, `sbom`, and a `qa` aggregate
(`lint`, `analyse`, `test`, `license-check`, `audit`). Also run `composer audit
--no-dev` in CI to block known-vulnerable deps.

## 9. Documentation (DX-first)

Every package ships a `/docs` folder matching the sibling packages' shape:

```
docs/
  index.md                     # what it is, the mental model, when to use it
  getting-started/
    installation.md
    quickstart.md              # zero-to-working in one read
  cookbook.md                  # task-oriented recipes
  architecture.md              # modules, kernels, contracts, data flow
  extending.md                 # customizing/overriding via contracts & config
  testing.md                   # the InteractsWith* traits & fakes, dogfooded
  security.md                  # threat model, crypto stance, supply chain, audit
```

Write for a developer adopting the package: understandable overview → quickstart →
recipes → deeper architecture → extension points. Keep it honest about scope and
limitations (e.g. "tamper-evident, not tamper-proof").

## 10. Commit discipline

- Conventional-commit subjects (`feat(module): …`, `fix(module): …`), with a body
  explaining the security/architecture reasoning when relevant.
- Verified-then-commit, one coherent change per commit. Keep `BUILD-STATUS.md` (or
  the package's equivalent living status doc) current so scope and gaps are always
  auditable.
- Branch off `main`; never commit or push unless asked.
