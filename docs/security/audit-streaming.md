---
title: Audit streaming — isolation & operator-only controls
description: The environment-isolation guarantee for SIEM streaming, and the SSRF/TLS toggles that must never be exposed to a tenant
weight: 11
---

# Audit streaming — isolation & operator-only controls

The [SIEM audit-streaming binding](../core-concepts/audit-streaming.md) exports the
platform's most sensitive data — the audit trail — to an external system. Two
invariants keep that safe.

## 1. Environment isolation is structural

A stream and its outbox rows are [environment-owned](../core-concepts/environments.md):
`AuditStream` and `AuditStreamDelivery` carry an `environment_id` and are bound by
the hard, always-on environment scope (deny-by-default: no ambient environment ⇒
zero rows). The guarantee is enforced at both stages:

- **Dispatch** runs inside the recording environment, so an env-A audit entry only
  ever lists and writes env-A streams.
- **Pump** runs on a worker with no ambient environment; `PumpAuditStream`
  reconstructs the stream's environment (`withoutScope` to read `environment_id`,
  then `runAs`) before any delivery row is loaded — so it can only ever load and
  ship that one environment's rows.

**A stream registered in environment B never receives an environment A event.** This
holds because the models are env-owned, not because of a filter that a future change
might forget. The single cross-environment step — `cbox-id:audit-streams:pump`
enumerating streams to *dispatch* a job each — reads only stream ids under
`withoutScope`; it never reads or delivers a delivery row across the boundary.

## 2. The SSRF and TLS toggles are operator-only — never expose them to tenants

The delivery engine (`cboxdk/laravel-siem`) is configured under the `siem.*`
namespace. Two keys are **safety controls, not tenant settings**:

- **`siem.http.verify_url`** — the SSRF guard on the stream endpoint. When on
  (the default), a stream URL is resolved and checked against loopback, private,
  link-local, reserved, and cloud-metadata ranges, and the connection is pinned to
  the validated IPs (no DNS-rebind window). It exists as a toggle only so a genuine
  single-tenant / on-prem install can reach an internal collector.
- **`siem.http.tls_verify`** — TLS certificate verification. On by default; turning
  it off logs a loud warning on every send.

> **Never surface either toggle in a tenant- or organization-facing UI or API.** A
> tenant that could set `verify_url = false` and then register a stream pointing at
> `http://169.254.169.254/…` or an internal service would turn audit streaming into
> an SSRF primitive — and could exfiltrate to, or probe, the platform's own
> infrastructure. These are deployment-level (operator) settings only. The
> per-environment thing a tenant *may* be allowed to configure is the destination
> URL and secret of *their own* SIEM — and that URL still passes the SSRF guard,
> precisely because the guard stays enabled.

## Honest scope

Streaming is **at-least-once and best-effort-ordered**; the customer SIEM
deduplicates on the event id (the entry hash) and can gap/reorder-check using the
`sequence` and `prev_hash` carried on every event. The hash chain is
tamper-*evident*, not tamper-*proof*: streaming to an independent system the operator
does not control strengthens the evidence, it does not make the trail
cryptographically immutable. Anchoring signed checkpoints externally (see
[audit](_index.md)) remains the stronger control.
