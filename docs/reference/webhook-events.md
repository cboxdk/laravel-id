---
title: Webhook events
description: Every webhook event the framework catalogues — what it means, what its payload carries, and which names are current, legacy or not yet emitted
weight: 3
---

# Webhook events

A webhook endpoint subscribes to event names (or `*` for all of them). Each delivery is an
HMAC-signed JSON envelope:

```json
{ "type": "membership.created",
  "sequence": 1,
  "data": { "organization_id": "01J…", "user_id": "01J…", "role": "member", "status": "active", "invited_by": null },
  "delivery_id": "01J…" }
```

`X-Cbox-Signature: t=<timestamp>,v1=<hex HMAC-SHA256 of "<timestamp>.<raw body>">`, with
`X-Cbox-Timestamp` beside it. `data.organization_id` is present on every event that belongs
to an organization.

## Rendering this list yourself

The list below is generated from `WebhookEventType::catalogue()`, and the package's test
suite fails if this page drifts from it. A console or an API renders the same source:

```php
use Cbox\Id\Webhooks\Enums\WebhookEventType;

WebhookEventType::offered();    // list<WebhookEventType> — what a subscription picker should show
WebhookEventType::catalogue();  // list<WebhookEventDescriptor> — group, label, description, status

foreach (WebhookEventType::catalogue() as $event) {
    $event->toArray(); // name, group, group_label, label, description, superseded_by, emitted, offered
}
```

- **current** — emitted, and the name to subscribe to.
- **legacy** — still emitted and delivered, beside the newer event named in its status; kept
  because existing endpoints subscribe to it. Not offered to new subscriptions.
- **not emitted** — catalogued, but the framework does not put it on the event bus, so a
  subscription to it would receive nothing. Not offered. No event has this status since 1.19,
  when the nine that were audit-only (domains, the SSO connection, the token vault, access
  reviews, `organization.settings_updated`) started being emitted; a test fails if a case is
  ever catalogued without an emitting source again.

The registry accepts any event name, catalogued or not, so a host or plugin that emits its
own events can be subscribed to as well.

## Catalogue

<!-- catalogue:start -->
### Users

| Event | Status | Description |
|---|---|---|
| `user.created` | current | A user account was created in the environment. Payload: `user_id`, `email`. |
| `user.updated` | current | A user's profile changed. Payload: `user_id`, `changed` (the fields that changed). |
| `user.deactivated` | current | A user was deactivated and can no longer sign in. Payload: `user_id`. |
| `user.login` | current | A user signed in through a federated (SSO) connection. Payload: `user_id`, `connection_id`. |
| `user.reactivated` | current | A deactivated user was reactivated. Payload: `user_id`. |
| `identity.linked` | current | An external identity (a social or enterprise login) was linked to a user. Payload: `user_id`, `provider`. |

### Organizations

| Event | Status | Description |
|---|---|---|
| `organization.created` | current | An organization was created. Payload: `id`, `slug`. |
| `organization.suspended` | current | An organization was suspended; its members are refused until it is reactivated. Payload: `id`, `status`. |
| `organization.reactivated` | current | A suspended organization was reactivated. Payload: `id`, `status`. |
| `organization.settings_updated` | legacy → `organization.updated` | Legacy name for a settings change; emitted alongside organization.updated. Payload: `id`, `keys` (the settings keys written). |
| `organization.updated` | current | An organization's name, slug or settings changed. Payload: `id`, `name`, `slug`, `changed` (which of `name`, `slug`, `settings`), and `settings_keys` for a settings change. |
| `organization.deleted` | current | An organization was archived — by an operator, or by its owner — and no longer grants access. Payload: `id`, `slug`, `status`. |
| `organization.archived` | legacy → `organization.deleted` | Legacy name for an archive; emitted alongside organization.deleted. Payload: `id`, `status`. |

### Memberships

| Event | Status | Description |
|---|---|---|
| `organization.member_added` | legacy → `membership.created` | Legacy name for a new membership; emitted alongside membership.created. Payload: `user_id`, `role`. |
| `organization.member_removed` | legacy → `membership.deleted` | Legacy name for a removed membership; emitted alongside membership.deleted. Payload: `user_id`. |
| `organization.member_role_changed` | legacy → `membership.updated` | Legacy name for a role change; emitted alongside membership.updated. Payload: `user_id`, `role`. |
| `membership.created` | current | A person joined an organization — added directly or by accepting an invitation. Payload: `user_id`, `role`, `status`, `invited_by`. |
| `membership.updated` | current | A member's tier in an organization changed. Payload: `user_id`, `role`, `previous_role`, `reason` (`role_changed` or `ownership_transferred`). |
| `membership.deleted` | current | A person stopped being a member of an organization, with every role they held there. Payload: `user_id`, `role` (the tier they had), `reason` (`removed` or `left`). |

### Invitations

| Event | Status | Description |
|---|---|---|
| `organization.invitation_created` | legacy → `invitation.created` | Legacy name for a new invitation; emitted alongside invitation.created. Payload: `email`, `role`. |
| `organization.invitation_accepted` | legacy → `invitation.accepted` | Legacy name for an accepted invitation; emitted alongside invitation.accepted. Payload: `user_id`. |
| `invitation.created` | current | Somebody was invited to join an organization. Payload: `invitation_id`, `email`, `role`, `invited_by`, `expires_at`. |
| `invitation.accepted` | current | An invitation was accepted and the membership created. Payload: `invitation_id`, `user_id`, `email`, `role`. |
| `invitation.revoked` | current | A pending invitation stopped working — revoked, or superseded by a newer invitation to the same address. Payload: `invitation_id`, `email`, `reason` (`revoked` or `superseded`). |

### Roles

| Event | Status | Description |
|---|---|---|
| `role.assigned` | current | A role was granted to a member in an organization. Payload: `user_id`, `role_id`. |
| `role.unassigned` | current | A role was taken away from a member in an organization — directly, or because the role was deleted. Payload: `user_id`, `role_id`. |
| `role.assigned_everywhere` | current | A role was granted to a user across the whole environment, in every organization. Payload: `user_id`, `role_id`. |
| `role.unassigned_everywhere` | current | An environment-wide role grant was taken away. Payload: `user_id`, `role_id`. |

### API keys

| Event | Status | Description |
|---|---|---|
| `api_key.created` | current | A customer API key was created for an app. Payload: the key id, `user_id`, `client_id`, its permissions and expiry — never the secret. |
| `api_key.revoked` | current | A customer API key was revoked and stops verifying. Payload: the key id, `user_id`, `client_id`. |

### Support access

| Event | Status | Description |
|---|---|---|
| `support_session.started` | current | A staff member started a time-boxed support session acting for a user in one app. Payload: the actor, the target user, the app, the reason and the expiry. |

### Directory sync (SCIM)

| Event | Status | Description |
|---|---|---|
| `directory.user.provisioned` | current | A user was created or updated by directory sync (SCIM). |
| `directory.user.deprovisioned` | current | A user was deleted by directory sync (SCIM). |
| `directory.user.deactivated` | current | A user was deactivated by directory sync (SCIM). |
| `directory.group.membership_changed` | current | A directory group's members changed through directory sync (SCIM). |

### Domains

| Event | Status | Description |
|---|---|---|
| `domain.added` | current | A domain was added to an organization, pending DNS verification. Payload: `id`, `domain`. |
| `domain.removed` | current | A domain was removed from an organization. Payload: `id`, `domain`. |
| `domain.verified` | current | A domain passed DNS verification and can route sign-ins to the organization's SSO. Payload: `id`, `domain`. |

### SSO connections

| Event | Status | Description |
|---|---|---|
| `connection.activated` | current | An SSO connection went live (once, on the change). Payload: `id`, `type`, `provider`, `name`. |

### Entitlements

| Event | Status | Description |
|---|---|---|
| `entitlement.set` | current | An entitlement was set for an organization for the first time. Payload: `key` and its value. |
| `entitlement.updated` | current | An organization's entitlement changed. Payload: `key` and its value. |
| `entitlement.revoked` | current | An entitlement was removed from an organization. Payload: `key`. |

### Token vault

| Event | Status | Description |
|---|---|---|
| `vault.grant.created` | current | An app was granted (or re-granted) leases of a token-vault secret. Payload: `secret_id`, `client_id`, `max_ttl_seconds` — never the credential. |
| `vault.grant.revoked` | current | An app's grant to a token-vault secret was revoked. Payload: `secret_id`, `client_id`. |
| `vault.secret.revoked` | current | A token-vault secret was revoked and can no longer be leased. Payload: `secret_id`, `provider`. |

### Access governance

| Event | Status | Description |
|---|---|---|
| `governance.access.revoked` | current | An access review took a grant away when its campaign closed. Payload: `campaign_id`, `user_id`, `access_type`, `access_ref`. |
<!-- catalogue:end -->
