---
title: Erasure (GDPR Art. 17)
weight: 20
description: What SubjectEraser removes, what it pseudonymises, why the audit trail keeps an opaque id, and how to add your own stores to the pipeline
---

# Security: erasure (GDPR Art. 17)

`SubjectEraser::erase($subjectId, $actor)` erases one person from every store the
package keeps them in, in **one database transaction**, and returns an `ErasureReceipt`
that says what it did, store by store, with counts. It runs in the current environment,
which must be the subject's.

```php
use Cbox\Id\Identity\Contracts\SubjectEraser;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;

$receipt = app(SubjectEraser::class)->erase($userId, AuditActor::operator($operatorId));

$receipt->count('passkeys');      // across every step
$receipt->step('oauth.grants');   // one step's counts
$receipt->toArray();              // for an API response or your Art. 30 records
```

The receipt carries no personal data — the opaque id, the placeholders written, and
numbers — so it is safe to log and to hand back to the person who asked.

## What happens

The steps run in registration order. Each module registers the steps for the data it
owns.

| Step | What it does |
|---|---|
| `identity.memberships` | Every membership removed through `Memberships::remove()` — so the organization's role grants go with it and `membership.deleted` reaches its webhooks — and every invitation addressed to the subject's email deleted. **Refused** (`ErasureRefused`) when the subject is the only owner of an organization; transfer ownership first. |
| `identity.sessions` | Every session revoked through the `SessionManager` (relying parties receive back-channel logout), and the IP address and user agent removed from every session row. |
| `identity.credentials` | Deleted: passkeys, TOTP factor, recovery codes, password history and age, a pending forced change, reset / verification / magic-link tokens, the lockout counter, and linked external identities (with the provider's raw claims). |
| `identity.api_tokens` | Personal API tokens and customer API keys the subject created, deleted in every organization. |
| `identity.event_payloads` | The email and name replaced with the placeholders in every domain-event outbox row about the subject. |
| `access_control.roles` | Remaining built-in RBAC grants, including environment-wide ones. With an external RBAC driver it reports that the host must erase there. |
| `oauth.grants` | Refresh tokens withdrawn and access tokens revoked (the same path deactivation uses), then unredeemed authorization codes, device codes, CIBA requests and session-participation rows deleted. |
| `token_vault.secrets` | Vault secrets owned by the subject deleted, with every grant to them. |
| `saml_idp.subject` | SAML IdP session records and pairwise NameIDs deleted. |
| `webhooks.deliveries` | Stored delivery payloads scrubbed like the outbox. |
| `provisioning.queue` | Undelivered SCIM create/update/reactivate operations cancelled (they would re-create the person downstream); every other queued operation's snapshot emptied. |
| `otp.challenges` | One-time-code challenges sent to the subject's email deleted. |
| `directory.users` | The inbound-SCIM copy of the person deleted. |

Then:

1. **The subject row is pseudonymised in place** by the `SubjectPseudonymiser`. The id is
   kept; email becomes `erased+<token>@erased.invalid` and name `erased-<token>`, where
   `<token>` is an HMAC of the id under a deployment secret
   (`cbox-id.erasure.pseudonym_key`, or a key derived from the crypto master key). The
   password hash and the verification stamp are dropped and the account is disabled.
   The same subject always gets the same placeholders, so a retried erasure is a no-op.
2. **A `user.erased` audit tombstone** is recorded — who asked, the subject's id, and the
   counts. No PII.
3. **A `user.erased` domain event** is emitted (payload: `user_id`). Webhook receivers
   should erase their copy. Outbound SCIM answers it with `DELETE /Users/{id}` on every
   connection that holds a remote record of the person, **whatever** that connection's
   deprovision policy — a deactivated remote record is still a copy of them.

If any step throws, the whole erasure rolls back and nothing above happened.

## The audit trail keeps an opaque id

Every column of an `audit_logs` row — actor, target, context, IP, timestamp — is inside
its hash (`CboxIdEntryCodec`), and each hash chains into the next. There is no unhashed
column to pseudonymise, and rewriting a hashed one breaks verification for every entry
after it, which is indistinguishable from tampering once a checkpoint is anchored. So the
eraser **does not touch past audit entries**. It appends the tombstone instead, and the
chain still verifies afterwards (a test proves it).

What that leaves, honestly:

- Past entries keep the subject's **opaque id** (a ULID). Once the subject row it points
  at is pseudonymised and every other store is erased, the id identifies nobody: it is
  not personal data on its own, and the tombstone tells an auditor why it resolves to an
  erased account.
- Some entries also carry **values that are personal data in their own right**: the IP
  address of sign-in and failed-sign-in events, and an email address as the target of
  invitation and verification events. Those cannot be removed without breaking the
  chain. Retaining them is a decision the controller documents under Art. 17(3)(b)
  (legal obligation) or 17(3)(e) (legal claims) — the trail exists as security evidence —
  together with a retention period after which the trail is exported and archived.
- The package does not reach into anything outside its own tables: your SIEM (if audit
  streaming is on), webhook receivers, downstream SCIM apps that failed the DELETE (the
  operation retries and dead-letters visibly), backups, and the upstream directory (if it
  pushes the person again, a new subject is provisioned).

## Your own stores

If your application keeps personal data about a subject, register a step so one call
erases it too:

```php
use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;

class CrmContactsErasureStep implements ErasureStep
{
    public function name(): string
    {
        return 'app.crm_contacts';
    }

    public function erase(ErasureRequest $request): ErasureStepResult
    {
        $deleted = CrmContact::query()->where('user_id', $request->subjectId)->delete();

        return ErasureStepResult::of($this->name(), ['crm_contacts' => $deleted]);
    }
}

// In a service provider:
$this->callAfterResolving(ErasureSteps::class, fn (ErasureSteps $steps) => $steps->register(new CrmContactsErasureStep));
```

A step runs inside the eraser's transaction, must be idempotent, and receives the email
and name captured **before** anything ran (`$request->email`, `$request->name`) along
with the placeholders to write instead (`$request->pseudonym`). Registering a step under
an existing name replaces it.

If you resolve subjects from your own store (`cbox-id.subject.resolver`), bind your own
`SubjectPseudonymiser` too. The default only rewrites the package's users table and
otherwise reports `subjectPseudonymised: false` on the receipt.

## Not covered

- **Platform operators** are not subjects; erase an operator through your own operator
  procedure.
- **Access-review history** (`governance_*`) and relationship tuples keep the subject id,
  like the audit trail, as records of decisions taken.
- **Support sessions** keep the actor and target ids and the stated reason.
