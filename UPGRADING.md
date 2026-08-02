---
title: Upgrading
description: Breaking changes and the migration each one needs, newest first
weight: 3
---

# Upgrading

Breaking changes only, newest first. Everything else is in [`CHANGELOG.md`](CHANGELOG.md).

The entries here are the ones that change behaviour for a deployment that is already
running. Read the whole section for the version you are crossing before you deploy — two
of the changes below fail **silently** (nothing is logged, nothing 500s) and one of them
fires on clients you do not control.

## 0.79.0

**Persistent and transient SAML NameIDs change value.** Until now the format was never
consulted: a service provider registered with `nameid-format:persistent` received
whatever `name_id_attribute` pointed at, which defaults to `email`. It now receives a
128-bit opaque identifier, per service provider, and a transient one gets a fresh value
per assertion.

At the service provider, that is **a different subject**. An SP that auto-provisions will
create a second account for the same person; one that does not will refuse the sign-in.

- **Who is affected:** only service providers deliberately registered as `persistent` or
  `transient`. The column default is `emailAddress`, so a registration that was never
  changed is unaffected.
- **What to do:** decide per SP. Either tell the SP to re-link its accounts (the usual
  answer — the new identifier is what the spec always meant by "persistent"), or set that
  SP's `name_id_format` back to `emailAddress`, which restores the old value exactly.
- **Reverting after the fact:** the identifiers are rows in `saml_idp_name_ids`, keyed
  `(environment_id, sp_entity_id, subject_id)`. Deleting a row reissues that one person's
  pseudonym at that one SP; nothing else is touched.

Adds one migration.

## 0.78.0

**The SAML HTTP-POST binding now carries its own Content-Security-Policy, and your host
has to let it.** A self-submitting cross-origin form is exactly what `form-action` and
the inline-script ban exist to refuse, so a host with a hardened policy was breaking its
own federation — the assertion was built, signed, and never delivered, with no
PHP-level symptom.

`SamlResponse::toPostBinding()` returns the payload together with a policy naming only
the registered ACS. **If your application sets a Content-Security-Policy in middleware,
it must not overwrite one the response already set** — otherwise this release changes
nothing for you and the blank-page failure continues.

The one-line shape, in whatever middleware stamps your headers:

```php
if ($name === 'Content-Security-Policy' && $response->headers->has($name)) {
    continue;
}
```

Defer only the CSP. Leaving the rest unconditional means a response cannot quietly drop
`frame-ancestors` or `nosniff` by setting one header.

`toPostForm()` is unchanged and still returns the same HTML, so a host with no policy at
all needs to do nothing.

## 0.77.0

### `saml_idp_sessions` (migration), and SLO stops working for pre-existing sessions

Additive table recording each issued assertion. Run migrations as usual.

**Behaviour change worth planning for:** Single Logout now resolves a NameID through the
service provider that presented it, and the record only exists for assertions issued from
0.77.0 onward. So an SP logging out a user who signed in BEFORE the upgrade finds no
record and the logout is a silent no-op — the user stays signed in at the IdP until their
session expires normally.

That window closes on its own as people sign in again. It is the safe direction of the
trade: before this, the same endpoint let any registered SP end any user's session by
naming their email address.

Records are kept 30 days.

## 0.73.0

### `Subjects` gained `update()`

Only affects a host that implements `Cbox\Id\Identity\Contracts\Subjects` itself —
a fatal error at boot, which is the failure mode you want.

Implement it as "apply the given name and/or email, leave a null alone, audit the change
and emit `user.updated`". A changed email MUST clear `email_verified_at`: an administrator
asserting an address is not its owner proving one.

**Worth doing anyway:** if your console changes a profile by writing to the model
directly, switch it to this. That path writes no audit entry for the account's primary
identifier and its recovery channel, and emits nothing — so outbound SCIM never learns
about it.

## 0.68.0

### `AuthPolicies` gained `overridesFor()`

Only affects a host that implements `Cbox\Id\Identity\Contracts\AuthPolicies` itself.
Adding a method to an interface is a fatal error at boot for any class implementing it,
which is the failure mode you want.

Implement it as "return the overrides for these organization ids, keyed by id, omitting
the ones with no override". The shipped `DatabaseAuthPolicies` is the reference. A
correct-but-slow implementation is three lines:

```php
public function overridesFor(array $organizationIds): array
{
    return array_filter(array_combine(
        $organizationIds,
        array_map(fn (string $id): ?AuthPolicy => $this->overrideFor($id), $organizationIds),
    ));
}
```

That works, but it is the shape the method exists to replace — it is called once per
authenticated request, so a single `whereIn` is worth writing.

Hosts using the shipped binding need to do nothing.

## 0.67.0

### `memberships` gains an index (migration)

Additive: `(user_id, created_at, id)`. No behaviour change, no backfill. On a large
`memberships` table the index build takes a lock proportional to its size — on Postgres,
consider `CREATE INDEX CONCURRENTLY` by hand and marking the migration as run, if that
table is big enough for the lock to matter.

## 0.66.0

### `Mfa` gained a `disable()` method

Only affects a host that implements `Cbox\Id\Identity\Contracts\Mfa` itself. Adding a
method to an interface is a fatal error for any class implementing it, so this one breaks
at boot rather than silently — which is the failure mode you want.

Implement it as "remove every factor and every recovery code for this user, and record
it". The shipped `MfaService` is the reference. If your implementation delegates to the
package's, forward the call.

Hosts using the shipped binding need to do nothing.

**Worth doing anyway:** if your console resets a user's MFA by deleting `MfaFactor` and
`MfaRecoveryCode` rows directly — which was the only way to do it before this release —
switch it to `Mfa::disable()`. The direct-delete path writes no audit entry, so the most
privileged MFA action in your deployment is currently the only one leaving no trace.

### `setCapture()` now refuses an unverified domain

`DomainVerification::setCapture($id, true)` throws
`Cbox\Id\Federation\Exceptions\DomainNotVerified` when the domain's DNS challenge has
not been answered. Previously it succeeded, and whether that was allowed depended on
which caller you went through.

Catch it wherever you expose domain settings and show the challenge record rather than a
generic failure. Disabling capture is unchanged and still always permitted.

Check for rows already in that state before deploying — capture on an unverified domain
means someone else's email domain may currently be routing to one of your organizations:

```sql
SELECT id, organization_id, domain FROM verified_domains
WHERE capture = 1 AND verified_at IS NULL;
```

Existing rows keep working; this release stops NEW ones being created, and does not
retroactively switch capture off — that call is yours, since it changes where those users
land at sign-in.

### The SAML replay ledger is re-keyed (migration)

`consumed_assertions` drops `unique(assertion_id)` and gains `environment_id` +
`connection_id`, keyed together. Run migrations as usual.

No backfill and no downtime concern: every row in this table expires inside the
assertion's own validity window, ten minutes at the outside, so by the time a deploy
finishes they are all dead. Existing rows keep an empty `connection_id`, which pairs
with their already-unique assertion id.

If you query this table directly — an unusual thing to do — note that `assertion_id`
alone is no longer unique, and deliberately so: it is chosen by the issuing identity
provider and only unique within it.

## 0.65.0

### `EntitlementSource::License` is removed

Only affects a deployment that ran `cboxdk/laravel-id-licensing` **with a real key** —
without one the plugin was inert and wrote nothing, and the framework itself never
wrote this source at all.

Check before upgrading:

```sql
SELECT count(*) FROM entitlements WHERE source = 'license';
```

Any rows must be moved to a source that still exists, or reading them throws when the
enum can no longer resolve the value:

```sql
UPDATE entitlements SET source = 'manual' WHERE source = 'license';
```

`manual` is the honest replacement: the grant now stands on its own rather than on a
licence, which is exactly what retiring the licensing layer means.

### `Accounts::suspend()` and `Accounts::reactivate()` take an actor

**This is a signature change and it will not compile until you fix your call sites.**

```php
- $accounts->suspend($accountId);
- $accounts->reactivate($accountId);
+ $accounts->suspend($accountId, $operatorId);
+ $accounts->reactivate($accountId, $operatorId);
```

**Why.** Suspending an account is the widest access revocation the platform has — every
member, every API key, every environment the account owns, at once. It was the only
such verb in the package that took no actor and wrote no audit entry, while
`Organizations::suspend()` and `PlatformOperators::suspend()` both audit internally.
That asymmetry pushed the audit write out to the call site, where the second caller
silently forgets it. Both verbs now record `account.suspended` / `account.reactivated`
on the system chain themselves.

**Also**: both are now genuinely idempotent. Suspending an already-suspended account,
or an id that does not exist, writes nothing and audits nothing — previously the blind
`update()` was a no-op but there was no entry either way. If you were relying on
re-suspension to produce a fresh audit entry, you were not: there was none.

### `Organizations::archive()` — new, and the way `Deleted` should be reached

`OrganizationStatus::Deleted` had no verb behind it, so hosts wrote the status onto the
model and called `save()`. That skips the domain event and, worse, leaves no audit
entry for the most destructive state an organization can enter.

```php
- $organization->status = OrganizationStatus::Deleted;
- $organization->save();
+ app(Organizations::class)->archive($organization->id, $operatorId);
```

Emits `organization.archived`, audits it against the actor, and is idempotent. Not
breaking unless you implement the `Organizations` contract yourself — in which case
you need the new method.

### `OrganizationStatus::revokesAccess()` — use it instead of comparing cases

**If your gate tests `status !== OrganizationStatus::Suspended`, or matches on
`Suspended` alone, you have a live authentication bypass.** A `Deleted` organization
went on authenticating its members, consenting on their behalf and minting tokens,
because nothing in the package answered whether a status revokes access and every
consumer re-derived it.

```php
- if ($organization->status === OrganizationStatus::Suspended) { deny(); }
+ if ($organization->status->revokesAccess()) { deny(); }
```

The method is an exhaustive `match` with **no `default`**, deliberately: a status added
in a later release fails static analysis at your call site instead of silently
inheriting "access allowed", which is exactly how `Deleted` slipped through.

### Do this BEFORE you deploy

**Run `php artisan migrate`.** One new migration,
`2026_07_26_000100_convert_char_columns_to_varchar`, re-types 225 identifier columns
from `char` to `varchar`. On PostgreSQL and MySQL/MariaDB it **rewrites 81 tables**
under an exclusive lock, one `ALTER TABLE` each. On SQLite it does nothing. Sizing,
locking and rollout order are below — read them before you run it on a large
database.

There is no code change to coordinate with it: old code and new code both work
against either schema, in both directions.

**If you published the migrations** (`--tag=cbox-id-migrations`), also re-publish them
with `--force`. A published copy keeps the package's filename, so it *overrides* the
package's version — your copies still say `$table->ulid()`, and a database built fresh
from them would come back padded. The new `ALTER` is not in your published set, so it
loads from the package and fixes your existing database either way; re-publishing is
what stops the next fresh install regressing.

**Decide, deliberately, whether to enable audit checkpointing.** It ships **off**, and
turning it on is a **one-way door**. Read the next section before you touch the flag.

---

### Audit checkpointing exists now — and the order you enable it in is permanent

**What was broken.** `AuditLog::checkpoint()` had three callers: two pass-through
decorators and a test. **Nothing scheduled it**, so `audit_checkpoints` was empty on
every deployment, `verifyCheckpointAnchor()` returned `null` on every call, and the
tail-deletion detection the whole design rests on never ran. The chain detects
modification and sequence gaps by itself; it cannot detect **truncation** — delete the
newest N entries and what is left is a shorter, perfectly valid chain. A signed
checkpoint is the only thing that catches that, and there were none.

**What is new.** `php artisan cbox-id:audit:checkpoint` signs a checkpoint over every
`(environment, scope)` chain that has advanced since its last one — idempotent, safe to
run beside live appends, `--dry-run` to see what it would do. It can be scheduled daily
with `cbox-id.audit.checkpoint.schedule`.

**That flag defaults to `false`, and that is not an oversight.**

A checkpoint is a signature over the chain's hashes **as they are today**, meant to be
exported and anchored somewhere append-only. The GDPR-erasure design still to come needs
exactly one **re-chain** of the existing rows: encrypt `ip` and `context` and hash the
**ciphertext** instead of the plaintext, so that destroying a per-subject key leaves
every hashed byte unchanged and `verifyChain()` still passes bit-for-bit. Every
checkpoint signed *before* that re-chain would afterwards report tampering that never
happened — permanently, and on evidence you may already have handed to a third party.

Because nothing has ever signed one, that window is still open. **The first checkpoint
closes it.**

So enable it in this order, and only this order, if a re-chain is in your future:

1. **Sign and retain, out of band**, each chain's current head hash and row count —
   `cbox-id:audit:checkpoint --dry-run` prints the head sequence per chain, and
   `select environment_id, scope, count(*), max(sequence) from audit_logs group by 1, 2`
   gives the counts. Keep that attestation somewhere this package cannot rewrite. It is
   what covers the gap while no checkpoint exists.
2. **Introduce `chain_version` and ciphertext hashing** (not in this release).
3. **Run the one-time re-chain** (not in this release).
4. **Then** set `CBOX_ID_AUDIT_CHECKPOINT_SCHEDULE=true`.

**If no such migration is in your future — turn it on now.** A deployment that will
never re-chain gains nothing by waiting and is, until it does, running an audit trail
whose truncation nobody would notice. That is the trade this default makes: it protects
a migration that has not happened yet, at the cost of a control that is not yet on.

```dotenv
CBOX_ID_AUDIT_CHECKPOINT_SCHEDULE=true
CBOX_ID_AUDIT_CHECKPOINT_TIME=02:40
```

---

### The audit chain's first entry no longer deadlocks on MariaDB

No action, and no migration — but if you run **MariaDB** and have seen
`SQLSTATE[40001] … 1213 Deadlock` come out of an audit append, this is it.

Appending serialises on the chain's **anchor** (sequence 1). On an *empty* chain there
is no anchor yet, and the locking read that looked for it matched no row — which InnoDB
answers with a **gap lock**. Eight processes opening one brand-new chain each held that
gap lock and each then needed an insert-intention lock inside it; MariaDB 11.8 resolved
the pile-up as a deadlock rather than the duplicate key the append is written to absorb,
and `DB::transaction(…, attempts: 3)` ran out of attempts. Measured at **6 of 800**
appends lost on MariaDB 11.8.8, 800/800 on MySQL 8.4 and PostgreSQL 16.

The anchor is now *found* with a plain read and *locked* by **primary key** — an exact
primary-key match takes a record lock and can never take a gap lock — and the search
runs **outside** the transaction, because under `REPEATABLE READ` a search inside it
would fix the snapshot the head read is then answered from. Serialisation failures also
retry on the append's own ladder now, with a jittered backoff. Same test, same engine:
**800/800**, six runs.

Failures were loud, not silent, so nothing was lost quietly and there is nothing to
repair.

---

### Identifier columns are `varchar(26)`, not `char(26)`

**What was broken.** `$table->ulid($column)` is `$table->char($column, 26)`, and
PostgreSQL implements `CHAR` as the SQL-standard `bpchar` — *blank-padded* character.
A value shorter than the declared width is physically stored padded out to it, and
PDO hands those bytes to PHP verbatim:

```
INSERT 'env_test' INTO char(26)
  octet_length(id) = 26      -- padded on disk
  length(id)       = 8       -- Postgres' own length() strips trailing blanks
  id = 'env_test'            -- true; the = operator strips them too

read back through PDO:
  strlen($v)          = 26
  $v === 'env_test'   = FALSE
```

Every check at the SQL level passes, which is why this survived sixty-one releases:
it is invisible from a SQL client. PHP is where it breaks, and it breaks every strict
comparison. Two that matter:

- `BelongsToEnvironment` compares a row's `environment_id` against the active
  environment key and throws `CrossEnvironmentAccess` **on the row's own
  environment** — `row belongs to [env_test⎵⎵⎵…], acting as [env_test]`.
- `DatabaseAuditLog::canonicalPayload()` puts `organization_id` inside the chain hash.
  It hashes the unpadded value at write and the padded one at read, so `verifyChain()`
  reports `content hash mismatch (tampered)` on a chain nobody has touched.

**338 of 1358 tests failed this way on postgres:16.** MySQL and MariaDB pad on disk
too but strip on retrieval, and SQLite has no fixed-width type at all, so neither
engine ever showed it — and the suite ran on SQLite.

**Does it affect you?** Only if an id in your database is shorter than its column.
Real ULIDs are exactly 26 characters, so a deployment whose ids were all generated by
this package is *unaffected in practice* — nothing pads. It bites the moment one
short id gets in: a seeded fixture, an imported tenant, a synthetic id from an
integration, or a hand-written `environment_id`. Check for one before you decide this
is theoretical:

```sql
-- PostgreSQL. Any row returned is a live instance of the bug.
SELECT count(*) FROM environments WHERE octet_length(id) <> length(id);
SELECT count(*) FROM audit_logs   WHERE octet_length(organization_id) <> length(organization_id);
```

**What changed.** The create migrations now say `$table->string($column, 26)`, which
fixes a database created from here on. The new migration is what fixes one that
already exists — casting `bpchar` to `varchar` strips the trailing blanks, so padded
values already on disk come back clean without a backfill.

**What it costs to run.**

| | |
|---|---|
| Statements | 81 — one `ALTER TABLE` per table, every column of that table in it, so each table is rewritten once rather than once per column. Plus 10 drops and 10 re-creates on MySQL/MariaDB, for the foreign keys |
| Lock (PostgreSQL) | `ACCESS EXCLUSIVE` on the table being altered; `SHARE ROW EXCLUSIVE` on any table holding a foreign key into it |
| Lock (MySQL/MariaDB) | Exclusive metadata lock per `ALTER`; InnoDB copies the table |
| Table rewrite | **Yes**, on all three server engines — `char` and `varchar` have different physical representations, so this is not a catalog-only change |
| Indexes and unique constraints | Rebuilt in place under their **existing names** |
| Foreign keys (PostgreSQL) | Kept in place; Postgres re-validates them across the type change |
| Foreign keys (MySQL/MariaDB) | **Dropped and recreated** — see below |
| SQLite | Skipped entirely — its declared types carry affinity, not width |
| Re-runnable | Yes. The current type is read from the live schema, so an already-`varchar` column is skipped and the width is taken from the column rather than assumed |
| Verified | Upgraded v0.61.0 database vs fresh install, schema dumps diffed on **PostgreSQL 16, MySQL 8 and MariaDB 11**: zero lines of difference on all three, all 10 foreign keys present |

**The 10 foreign keys on MySQL and MariaDB are dropped and put back.** InnoDB refuses
to re-type a column a foreign key sits on when that would leave the two sides
mismatched (`error 1832`), and they always are mismatched for a moment: the two sides
live in different tables, so they cannot be altered in one statement. PostgreSQL has
no such objection and keeps its constraints in place throughout.

So on MySQL/MariaDB there is a window — the length of the whole conversion — in which
the account-plane foreign keys are **not enforcing**. The constraints are read back
from the live schema and restored with the same names, columns and referential
actions, so the end state is identical either way; but if you are running MySQL under
write traffic, that window is the reason to take a maintenance window rather than
rely on the constraints during the deploy.

If a conversion fails while the keys are down, the migration puts back every one that
will go back before it rethrows. A **hard kill** in that window — SIGKILL, a lost
node — leaves them dropped, and re-running will not bring them back, because nothing
outside the running process recorded what they were. Check for that before you assume
the deploy was clean, and recreate any that are missing from your schema:

```sql
-- MySQL/MariaDB. Expect 10 on a stock install.
SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
WHERE CONSTRAINT_SCHEMA = DATABASE();
```

None of this applies on PostgreSQL, where the constraints are never dropped.

**Sizing it.** The cost is a full rewrite of every listed table, so it scales with
your row count — `audit_logs` first, since it is the highest-row-count table in the
system. On a **near-empty** database the whole migration measured 6–16s on PostgreSQL
16 and 22–84s on MySQL 8 and MariaDB 11 (the spread is host load, not data — these
were containers on a laptop; a real server is faster). That is the fixed overhead of
81 table rewrites with nothing in them, so treat it as the floor and add your own
data. Get a number before you schedule it:

```sql
SELECT relname, n_live_tup, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10;
```

**Do you need a maintenance window?** If those tables are small — tens of thousands
of rows — this is seconds and a normal deploy absorbs it. If `audit_logs` is large,
take a window: `ACCESS EXCLUSIVE` blocks reads *and* writes on that table for the
whole rewrite, and it needs disk headroom for a second copy of each table while it
runs. The migration is deliberately **not** wrapped in a transaction, so each table
commits as it completes and an interruption leaves the tables done so far converted
and the rest untouched — re-running finishes the job.

**On PostgreSQL, set a `lock_timeout` first — this matters more than the rewrite.**
`ACCESS EXCLUSIVE` has to *wait* for every transaction already touching the table,
and while it waits it queues **ahead of** every new reader. One long-running query on
`audit_logs` therefore turns a sub-second `ALTER` into a stall of everything reading
that table, for as long as that query runs. Bounding the wait turns that from an
outage into a retry:

```sql
SET lock_timeout = '3s';   -- in the session that runs the migration
```

The `ALTER` then fails fast with `55P03 lock_not_available` instead of blocking the
application, and the migration can simply be re-run — it is idempotent, and picks up
where it left off.

**Rollout order — migration first, then code, and nothing to coordinate.** The
schema change is invisible to PHP: a `varchar(26)` and a `char(26)` both come back as
strings, and the only difference is that the `varchar` is not padded. So

- old code against the new schema works — it just stops seeing padding, which is the
  bug being fixed;
- new code against the old schema works — it is the behaviour that shipped for
  sixty-one releases.

There is no window in which a half-rolled-out deploy is inconsistent, and `down()`
restores the original `char` types exactly (verified by the same `pg_dump` diff, in
reverse).

**One column set worth naming.** `log_streams` and `stream_deliveries` belong to
`cboxdk/laravel-siem`, whose own create migration still calls `$table->ulid()`. This
package cannot edit it, so those three columns are converted by this migration on
**every** install, fresh or upgraded. That is why the migration does real work even on
a brand-new database.

---

## 0.61.0

### Do this BEFORE you deploy

**Nothing, if you run PostgreSQL or SQLite.** No migration is added and none of the
existing ones is edited in a way that touches a database that has already run them.
Read the note below anyway if you care about schema drift, or if you are about to
stand up a MySQL/MariaDB deployment.

---

### The migrations now run on MySQL and MariaDB (they never did)

**What was broken.** `docs/requirements.md` promised "any database Laravel supports —
MySQL/MariaDB, PostgreSQL, SQLite, SQL Server". On MySQL, `php artisan migrate` died on
the fifth table: twenty `json` columns carried a literal `DEFAULT '{}'` / `DEFAULT '[]'`,
which MySQL has never permitted on a BLOB/TEXT/JSON column (error 1101). Behind that were
three more walls — two composite indexes over the InnoDB 3072-byte key limit, and two
generated index names over the 64-character identifier limit. The suite ran only on
sqlite, which has none of those limits, so nothing ever said so.

**What changed.** `json` defaults now go through
`Cbox\Id\Kernel\Database\JsonDefault`, which emits `DEFAULT (json_object())` /
`DEFAULT (json_array())` on MySQL and MariaDB and the **unchanged literal** everywhere
else. Some columns that sit inside composite indexes were given explicit lengths, and
three over-long index names were shortened.

**Effect on an existing PostgreSQL database: none.** The emitted DDL for `pgsql` is
byte-identical for every `json` default — verified by diffing the full pretend-migration
output before and after. Nothing re-runs on a database that has already migrated.

**One divergence worth knowing about.** A database created *before* this release and one
created *after* it are not structurally identical, because the length and name changes
live in the original `create` migrations rather than in a new `ALTER`:

| | Before | Now |
|---|---|---|
| `relationship_tuples.object_type`, `relation`, `subject_type`, `subject_relation` | `varchar(255)` | `varchar(64)` |
| `relationship_tuples.object_id`, `subject_id` | `varchar(255)` | `varchar(128)` |
| `vault_secrets.name`, `owner_type`, `owner_id` | `varchar(255)` | `varchar(128)` |
| `audit_logs.environment_id`, `audit_checkpoints.environment_id` | `varchar(255)` | `varchar(64)` |
| `audit_logs.target_type` | `varchar(255)` | `varchar(64)` |
| index `relationship_tuples_organization_id_object_type_object_id_relation_index` | (truncated to 63 chars by PostgreSQL) | `relationship_tuples_org_object_relation_index` |
| constraint `provisioned_resources_environment_id_connection_id_user_id_unique` | (truncated) | `provisioned_resources_env_connection_user_unique` |
| index `external_action_endpoints_environment_id_hook_point_status_index` | (truncated) | `external_action_endpoints_env_hook_status_index` |

This is deliberate. Converging the two would mean an `ALTER TABLE` that rewrites
`audit_logs` — the highest-row-count table in the system — on every existing PostgreSQL
deployment, to fix a limit PostgreSQL does not have. The new widths are strictly
narrower, so any value a new install accepts an old one already accepts; the risk runs
one way only. If you want the schemas identical, write the `ALTER` yourself against a
maintenance window, after checking `max(length(...))` on each column.

## 0.58.0

### Do this BEFORE you deploy

1. **Update every call to `Memberships::add()`, `Memberships::changeRole()` and
   `Invitations::invite()`.** The `$role` parameter is now a `MembershipRole` enum, not a
   string. This breaks at compile/type level, so it will not slip past you silently — but
   it does break every host call site.
2. **If you implement `Federation\Contracts\Connections` yourself, add two methods.**
   `samlConfig()` and `oidcConfig()`. Nothing else about the interface changed.
3. **If you call `SamlSettings` directly, pass a `SamlConnectionConfig`.** It no longer
   takes an array, and `SamlSettings::slsUrl()` moved onto the value object.

Each is expanded below.

---

### Membership roles are an enum on the contract, not a string

**What changed.**

```diff
-public function add(string $organizationId, string $userId, string $role, ?string $invitedBy = null): Membership;
+public function add(string $organizationId, string $userId, MembershipRole $role, ?string $invitedBy = null): Membership;

-public function changeRole(string $organizationId, string $userId, string $role): Membership;
+public function changeRole(string $organizationId, string $userId, MembershipRole $role): Membership;

-public function invite(string $organizationId, string $email, string $role, ?string $invitedBy = null): PendingInvitation;
+public function invite(string $organizationId, string $email, MembershipRole $role, ?string $invitedBy = null): PendingInvitation;
```

`ImportOptions::$defaultRole` changes with them: `string $defaultRole = 'member'` becomes
`MembershipRole $defaultRole = MembershipRole::Member`.

**Why.** The role is authorization data — the last-owner guard and the console's
isOwner/isAdmin checks turn on it. The service already parsed it with
`MembershipRole::from()` internally, so a typo'd role was an uncaught `ValueError` (a 500)
deep inside a transaction rather than a validation failure, and static analysis could not
see it at all. The enum's own docblock states the goal the string signature defeated: an
invalid role should be unrepresentable.

It also fixes a quieter divergence: the audit payload recorded the caller's RAW string
while the row persisted the parsed enum, so a case-variant input made the audit trail
disagree with the stored role. Both now record the same enum-backed value.

**What to do.** Pass the enum:

```diff
-app(Memberships::class)->add($org->id, $user->id, 'admin');
+app(Memberships::class)->add($org->id, $user->id, MembershipRole::Admin);
```

Parse untrusted input (an HTTP field, a CSV cell) at the edge, where a bad value is a
validation failure you can report:

```php
$role = MembershipRole::tryFrom($request->string('role')->toString());

abort_if($role === null, 422, 'Unknown role.');
```

`tryFrom()` is case-sensitive and returns `null` — it never guesses.

**Related, non-breaking:** `Invitation::$role` is now cast to `MembershipRole` (the column
is unchanged; no migration). `cbox-id:users:import` validates `--role` up front and fails
with the accepted list instead of erroring mid-run, and an unrecognized role in an import
row is now a per-row `ImportError` naming the accepted roles rather than a raw
`ValueError` message.

---

### Federation connection configs are parsed value objects

**What changed.** `Federation\Contracts\Connections` gains two methods:

```php
public function samlConfig(Connection $connection): SamlConnectionConfig;
public function oidcConfig(Connection $connection): OidcConnectionConfig;
```

`config(): array` is unchanged and still there — it is the unseal half of the JSON
persistence boundary — but it is no longer how the config should be READ. `create()` is
also unchanged: it still takes an array, because a DRAFT connection is deliberately
allowed to be incomplete.

`SamlSettings::for()` and `SamlSettings::toArray()` now take a `SamlConnectionConfig`
instead of an array, and `SamlSettings::slsUrl(array $config)` is gone — it is
`$config->slsUrl()` on the value object.

**Why.** The config is durable, admin-authored configuration that four subsystems read
(assertion validation, SP metadata, SP-initiated login, Single Logout). As an
`array<string, mixed>` each of them re-read the same string keys and re-validated the
same shape across roughly two dozen sites, so adding one field — `jwks_uri` was the
motivating case — meant finding every reader.

**Behaviour note.** Required fields are asserted once, when the config is read, and the
error names the missing key exactly as before. One case tightened: reading a connection
as the wrong protocol (`oidcConfig()` on a SAML connection) now raises a message that
says so, instead of a confusing "missing [idp_entity_id]".

**What to do.**

```diff
-$config = $connections->config($connection);
-$settings = SamlSettings::toArray($config);
-$slo = SamlSettings::slsUrl($config);
+$config = $connections->samlConfig($connection);
+$settings = SamlSettings::toArray($config);
+$slo = $config->slsUrl();
```

**Related, non-breaking:** two Federation collaborators the HTTP layer drives are now
published as contracts and bound as singletons, matching every other collaborator in
the module — `OidcRelyingParty` (implemented by `OidcClient`) and `SamlSpSingleLogout`
(implemented by `Saml\SamlLogout`). The concrete classes still exist and still work; the
contracts are simply what you should type-hint and what you can rebind. Note the
SP-role name: `SamlIdp\Contracts\SamlSingleLogout` is the separate IdP-role interface.

---

## 0.57.0

### Do this BEFORE you deploy

1. **Run a queue worker.** Webhook delivery is no longer synchronous.
2. **Audit every registered client's scope list.** `invalid_scope` is now enforced at
   `/authorize`. This has the widest blast radius in the release.
3. **On PostgreSQL, reconcile case-variant duplicate usernames/emails.** Equality is now
   case-insensitive on every driver, so rows that used to coexist now collide.
4. **Re-read your published `config/cbox-id.php`.** Package defaults are now merged
   key-by-key instead of block-by-block, so settings a partial published config used to
   suppress are live again.

Each is expanded below.

---

### Webhooks require a running queue worker — SILENT if missing

**What changed.** `HttpWebhookDispatcher` used to make the outbound HTTP request in-band,
inside the relay pass. It now dispatches a `DeliverWebhook` job. The relay's job is to
enqueue; the worker's job is to deliver.

**Why.** One endpoint that accepts the connection and never answers used to hold the relay
pass open, delaying every other tenant's events behind it. Delivery also had no way to
recover a request the process died in the middle of.

**How it breaks.** A deployment with no worker consuming the queue enqueues jobs that are
never run. Deliveries sit at `pending`. **No exception is thrown and nothing is logged as
an error** — from the console the endpoint simply looks quiet. This is the failure mode
most likely to be mistaken for "no events happened".

**What to do.**

```sh
php artisan queue:work --queue=default
```

Run it under a supervisor (systemd, Supervisor, Horizon) so it restarts. If you already
run a worker for the framework's own queues, webhook jobs go on the same connection unless
you separate them:

```env
CBOX_ID_WEBHOOKS_QUEUE_CONNECTION=redis
CBOX_ID_WEBHOOKS_QUEUE=webhooks
```

`QUEUE_CONNECTION=sync` also "works" and restores the old inline behaviour — but it
reintroduces the head-of-line blocking the change exists to remove, so treat it as a
development setting only.

**How to check you got it right.** After deploying, trigger any event and confirm the
delivery leaves `pending`. `php artisan cbox-id:events:backlog --json` reports outbox depth;
a depth that only grows means the relay or the worker is not running.

See [Background work](docs/operations/background-work.md) for the full picture, including
the retry sweep, the stranded-delivery rescue and the per-endpoint circuit breaker.

### The root host now 404s the IdP surface

**What changed.** The protocol surface — OIDC discovery, JWKS, `/oauth/*`, SCIM — is now
behind a configurable middleware gate (`cbox-id.api.middleware`). In a multi-tenant
deployment the apex host refuses it.

**How it breaks.** A client pointed at the apex rather than at its environment's issuer
gets a `404`, where it previously got a working response. This looks exactly like an
outage.

**What to do.** Point clients at the issuer that discovery advertises, never at the apex.
The gate is inert in a single-tenant install (`cbox-id.api.middleware` defaults to `[]`),
so nothing changes there. See the deployment docs in the app repo for the host layout.

**Note:** `GET /up` is registered outside the gated group and still answers on every host,
so a liveness probe against the apex is unaffected.

### `invalid_scope` is enforced at `/authorize` — widest blast radius

**What changed.** A scope the client is not registered for used to be accepted at
`/authorize` and then quietly filtered out when the token was minted. It is now refused up
front with `error=invalid_scope`.

**Why.** The old behaviour turned a registration mistake into a mystery: the authorization
succeeded, the token came back missing a scope, and the client's next API call failed with
a 403 that nothing anywhere explained.

**How it breaks.** **Every deployed client whose SDK requests more scopes than it
registered now hard-fails at the authorize step instead of degrading.** You do not control
when those clients next run, and you cannot fix them from the server side after the fact.
The usual culprits are `email` and `offline_access` — SDK defaults that were never added to
the registration.

**What to do — before you deploy.** For every client, compare its registered scope list
against what its SDK actually sends:

```sh
php artisan tinker
>>> \Cbox\Id\OAuthServer\Models\Client::query()->get(['client_id', 'name', 'scopes']);
```

Add any scope that is legitimately requested. A client registered with **no** scopes at all
is exempt from the check — it has declared no surface to validate against — so an empty
list is not a false positive.

**Related, non-breaking:** `/oauth/token` now echoes the granted `scope` in its response, so
a narrowed grant is visible at the point it happens.

### SAML: stricter `AuthnRequest` handling

Four changes, all refusals that used to be acceptances:

- **`NameIDPolicy` is enforced** against what the registered SP can actually be answered
  under. A policy the registration does not support is refused instead of being answered
  under a different format. (`urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` still
  means "IdP, you choose" — note the **1.1** prefix. There is no `SAML:2.0:…:unspecified`;
  SAML 2.0 carries the 1.1 URN forward unchanged, and `NameIdFormat::tryFromPolicyUrn()`
  returns null for the 2.0 spelling, so an SP configured from an earlier revision of this
  line is answered `InvalidNameIDPolicy`.)
- **A signed `AuthnRequest` must carry a `Destination`.** A signed request with no
  `Destination` at all was previously accepted; it is now refused, because the signature
  then covers no statement about where the request was meant to go.
- **An `AuthnRequest` is single-use.** A replayed request id is refused.
- **An `AuthnRequest` older than 15 minutes is refused.**

**What to do.** If an SP integration starts failing, the refusal reason is in the audit
trail. A relying party that cannot supply `Destination` on a signed request must either
stop signing or be fixed; there is no configuration switch to re-accept it.

### SCIM: stricter errors, and one response-shape change

| Case | Before | Now |
|---|---|---|
| `DELETE` an id that does not exist | `204` | `404` |
| `PATCH` with malformed or absent `Operations` | `200` (silently no-op) | `400` |
| `active` sent as a non-boolean (`"fasle"`, `"no"`, `0`, `1`) | `200`, treated as false | `400` |
| Rate limited | plain framework `429` | `429` inside the SCIM Error envelope, `Retry-After` intact |
| `GET /Groups` (listing) | included `members` | **omits `members`** unless requested |
| Filter literal of the wrong type for its attribute | matched nothing, `200` | `400 invalidFilter` |

The `/Groups` change is the one that can break a working integration: a client that reads
membership from the listing now sees no members. Ask for them explicitly
(`?attributes=members`), or read the group singly — a single-resource `GET /Groups/{id}`
still returns members. The change exists because a page of large groups was a memory bomb.

The stricter errors are a net win for integrators (a rejected write is now visible instead
of being reported as a success it did not make), but a connector that treats any non-2xx as
fatal will start alerting on requests it used to send happily.

See [SCIM](docs/core-concepts/scim.md) for the full endpoint reference.

### `userName` / email equality is case-insensitive on ALL drivers

**What changed.** Comparison used to depend on the database's collation: case-insensitive
on MySQL's default collation, case-**sensitive** on PostgreSQL. It is now case-insensitive
everywhere, via normalized columns
(`2026_07_25_000100_add_normalized_scim_columns_to_directory_users`).

**How it breaks.** **A PostgreSQL tenant may hold rows that were legal before and are not
now** — `Alice@example.com` and `alice@example.com` as two separate directory users. After
the migration they collide, and a create or update that touches either returns
`409 uniqueness`.

**What to do — before you deploy.** Find the duplicates and merge or delete them:

```sql
SELECT directory_id, lower(user_name) AS key, count(*)
FROM directory_users
GROUP BY directory_id, lower(user_name)
HAVING count(*) > 1;

SELECT directory_id, lower(email) AS key, count(*)
FROM directory_users
WHERE email IS NOT NULL
GROUP BY directory_id, lower(email)
HAVING count(*) > 1;
```

The migration backfills `user_name_lower` / `email_lower` and indexes them; it does NOT
deduplicate. Decide which row survives for each collision —
this is a data decision, not a mechanical one, because the two rows may carry different
memberships. The migration itself does not merge them for you.

### `/up` returns JSON

`GET /up` now returns `{"status":"ok"}` with `Content-Type: application/json` instead of an
empty body. A probe asserting on an empty body or on `text/html` needs updating; a probe
asserting only on the status code is unaffected.

### Published config is merged key-by-key, not block-by-block

**What changed.** The package used to merge its defaults with Laravel's
`mergeConfigFrom()`, a single `array_merge()` that only merges the TOP level. It now uses
`Cbox\Id\Support\PackageConfigMerger`, which recurses.

**Why.** A published `config/cbox-id.php` is almost always PARTIAL — you override one
setting and delete the rest of the file. Under the old merge, naming a top-level key
replaced the package's ENTIRE block for that key. An app whose config declared nothing but

```php
'oauth' => ['authorization_endpoint_path' => '/oauth/authorize'],
```

silently lost `oauth.access_token_ttl`, `oauth.require_par`, `oauth.embed_entitlements`,
`oauth.decisions.*`, `oauth.ciba.*`, `oauth.dynamic_registration.*` and
`oauth.authorization_endpoint`. Every consumer inside the package passes a hard-coded
fallback to `config()`, so nothing crashed — but `CBOX_ID_ACCESS_TOKEN_TTL`,
`CBOX_ID_REQUIRE_PAR`, `CBOX_ID_DCR_MODE`, `CBOX_ID_DECISIONS_MAX_BATCH` and
`CBOX_ID_CIBA_*` were **inert**. Setting them did nothing and said nothing.

**The rules.**

- Your value wins on any key you define, including `null`, `false` and `0`.
- A package default is only ever filled in where your config is SILENT about that key.
- A **list** (sequential array — `api.middleware`, `oauth.dynamic_registration.allowed_scopes`)
  is treated as a single value: yours REPLACES the package's, it is never appended to. You
  can still shrink a default list, or empty it with `[]`.
- Where your value and the package's are different types, yours stands unmerged.

**How it breaks you.** Only in one shape: if you were relying on the shallow merge to
REMOVE a package default — omitting a sibling key so it disappeared entirely — that key is
now present again at its package default. Check any top-level block you published
partially. Package defaults are conservative (DCR `disabled`, PAR not required), so the
usual effect of getting them back is that an env var you set now takes effect. To keep a
default suppressed, state it explicitly:

```php
'oauth' => [
    'authorization_endpoint_path' => '/oauth/authorize',
    'embed_entitlements' => false, // explicit beats omitted
],
```

`php artisan cbox-id:doctor` and `php artisan config:show cbox-id` both print the merged
result, which is the fastest way to see what your deployment actually resolves.

---

## How to read this file

An entry earns a place here only if a deployment that was working can stop working, or
start behaving differently, without anyone changing their own code. Additive features,
new endpoints and bug fixes that only ever made a wrong answer right live in
[`CHANGELOG.md`](CHANGELOG.md).
