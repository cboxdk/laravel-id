---
title: Fine-grained authorization
description: An environment's own relationship model — a schema of resource types and relations, tuples written against it, and cached, consistency-token-aware checks and list queries (Zanzibar-style)
weight: 9
---

# Fine-grained authorization

Roles answer "may this person approve invoices in this organization?". Fine-grained
authorization answers "may this person edit **this** document?" — where the answer
depends on who owns the document, which folder it is in, who can see that folder, and
which group the person is in.

`FineGrainedAuthorization` gives each environment its own model for that, in the shape
of Google Zanzibar (and OpenFGA, SpiceDB and WorkOS FGA):

- a **schema** — the resource types and the relations on each, and how each relation is
  decided from the others;
- **tuples** — the facts your app writes: `document:readme#viewer@user:alice`;
- **checks** and **list queries**, evaluated over both, cached, and as fresh as you ask.

Everything is scoped to the ambient environment. Two environments never share a schema,
a tuple, a revision or a cached answer.

It sits beside the platform's own, organization-scoped
[`RelationshipStore`](authorization.md) (resource grants, groups): that store has a fixed
meaning the platform defines; this one holds a model the environment defines for its
app.

## The schema

```text
# Documents live in folders; a folder's viewers can read everything in it.
type user

type group
  relation member: [user, group#member]

type folder
  relation parent: [folder]
  relation owner: [user]
  relation editor: [user, group#member] or owner or editor from parent
  relation viewer: [user, group#member] or editor or viewer from parent

type document
  relation parent: [folder]
  relation owner: [user]
  relation editor: [user, group#member] or owner or editor from parent
  relation viewer: [user, group#member] or editor or viewer from parent
  relation blocked: [user]
  relation can_read: viewer but not blocked
```

A relation is decided by:

| Written | Means |
|---|---|
| `[user, group#member]` | the subjects a tuple may name directly: any `user`, or everybody who is a `member` of one group |
| `owner` | another relation on the same object (a computed userset) |
| `viewer from parent` | `viewer` on every object this one's `parent` tuples point at (tuple-to-userset) |
| `a or b`, `a and b`, `a but not b` | union, intersection, exclusion — `or` and `and` only mix with parentheses |

`#` starts a comment where it begins a line or follows a space.

The parser refuses, by line and all at once: unknown types and relations; a relation that
is only computed being written to; `x from p` where `p` is not a plain list of types or no
type it lists has `x`; more than one `[...]` list on one relation; and any **exclusion
whose subtracted side depends back on the relation it decides** ("a viewer, but not a
viewer" has no answer). Cycles that only add access — groups in groups, folders in
folders — are allowed and bounded at evaluation time.

```php
use Cbox\Id\Kernel\Authorization\Contracts\FineGrainedAuthorization;

$fga = app(FineGrainedAuthorization::class);

$fga->validateSchema($source);   // AuthorizationSchema, or InvalidSchema with every error
$fga->updateSchema($source);     // SchemaState; SchemaConflict if it would strand tuples
$fga->schema();                  // the source as written, the parsed model, its version
```

A schema change that would strand tuples already written — it drops a relation they are
on, or no longer takes the kind of subject they name — is refused with `SchemaConflict`,
listing them. Delete those tuples first: a schema change never removes access silently.

## Tuples

```php
use Cbox\Id\Kernel\Authorization\ValueObjects\Tuple;

$write = $fga->writeTuples(
    [Tuple::parse('folder:handbook#owner@user:olivia'), Tuple::parse('document:leave#parent@folder:handbook')],
    [Tuple::parse('document:leave#viewer@user:mallory')],   // deletes, same batch
);

$write->written;      // new tuples (re-writing an existing one is not an error, and not counted)
$write->consistency;  // the revision this batch produced
```

A batch (up to `max_batch`, default 100) is atomic and checked against the schema: an
unknown type or relation, a computed relation, or a subject the relation does not take
refuses the whole batch with `InvalidTuple`, naming the position. Ids are up to 128
printable characters without spaces, `#` or `@`; `*` on its own is reserved.

## Checks and list queries

```php
use Cbox\Id\Kernel\Authorization\ValueObjects\{Check, ResourceRef, SubjectRef};

$fga->check(Check::of('document', 'leave', 'viewer', SubjectRef::of('user', 'alice')))->allowed;

// Is every member of eng a viewer? (a userset as the subject)
$fga->check(Check::of('document', 'leave', 'viewer', SubjectRef::of('group', 'eng', 'member')));

$fga->checkMany([$check1, $check2]);   // one revision, answered in order

$fga->listResources(SubjectRef::of('user', 'alice'), 'viewer', 'document', limit: 100);   // ids, sorted, paged
$fga->listSubjects(ResourceRef::of('document', 'leave'), 'viewer', 'user', after: $cursor);
```

A check or list query naming a type or relation the schema does not define is refused
(`UnknownRelation`), never answered "no" — a typo would otherwise deny everybody.

### How they are evaluated

A relation means the least fixpoint of its definition: a subject has it when a finite
chain of tuples and rewrites derives it. A **check** searches for that chain depth-first.
A node already on the current path is a cycle and contributes nothing on that path; an
answer is remembered for the rest of the call when it is "yes", or a "no" that did not
depend on such a cut, so every node is expanded at most once per subject. The search is
bounded by `max_depth` (default 25); past it the check is **refused**
(`ResolutionTooComplex`) rather than answered — "no" would be wrong for a grant further
down, and wrong the other way inside a `but not`.

**List queries** walk the tuple graph as if every operator were a union — outward from the
subject using the schema's reverse edges for list-resources, inward from the resource for
list-subjects — bounded by `max_expansion` (default 50 000) visited nodes. Where the
relation is union-only all the way down, that walk is the exact answer; otherwise each
candidate is confirmed with a check.

The evaluator is tested against a reference implementation — a bottom-up, stratified
fixpoint that shares no code with it — on hundreds of random schemas and tuple graphs
with cycles, intersections and exclusions, in memory and through the database and cache.

## Revisions, consistency tokens and the cache

Each environment's model has one monotonic **revision**, advanced in the same transaction
as every write (a tuple batch that changed something, a schema change); the model's row
is locked for that transaction, so writes to one environment are serialized.

Every write and read answers with a **consistency token** — `<revision>.<environment
tag>` — and every read accepts one: the answer is then **at least as fresh** as the write
that produced it. When the connection read is behind the token (a lagging read replica),
the model and its tuples are re-read from the write connection. A token for a revision
the environment has not reached, or one minted by another environment, is refused
(`InvalidConsistencyToken`). Without a token a read is as fresh as the connection it
reads.

Answers are cached under `cbox-fga:<environment>:<revision>:<tag>:<question>`. A write
advances the revision, so the next read asks a key nothing has answered: invalidation is
immediate and atomic across cache nodes, and nothing is ever deleted. The tag is a random
value replaced with every revision, so an answer computed inside a transaction that later
rolled back can never be found again. The price is that any write cools that
environment's whole cache — the right trade for a model read far more than written.

## Configuration

```php
// config/cbox-id.php
'fga' => [
    'max_depth' => env('CBOX_ID_FGA_MAX_DEPTH', 25),
    'max_expansion' => env('CBOX_ID_FGA_MAX_EXPANSION', 50000),
    'max_batch' => env('CBOX_ID_FGA_MAX_BATCH', 100),
    'cache' => [
        'enabled' => env('CBOX_ID_FGA_CACHE', true),
        'store' => env('CBOX_ID_FGA_CACHE_STORE'),   // null = the default store
        'ttl' => env('CBOX_ID_FGA_CACHE_TTL', 3600),  // bounds memory, not freshness
    ],
],
```

## Storage and performance

Two tables: `fga_stores` (one row per environment: the schema and the revision) and
`fga_tuples`. Every query the evaluator makes is one range read on one of two indexes:
the unique **forward** key `(environment, resource type, resource id, relation, subject
type, subject id, subject relation)` for checks and list-subjects, and the **reverse**
index `(environment, subject type, subject id, subject relation, resource type,
relation)` for list-resources and tuple-to-userset walked backwards. A direct list is
decided in one read that returns the exact match and the usersets together, so a group
with ten thousand direct members costs one row, not ten thousand.

**Benchmark note.** The folders-and-documents schema above, on 24 306 tuples — 1 000 users
in 50 groups nested three deep, 200 folders in a five-way tree four levels deep, 20 000
documents, an editor grant on every seventh — SQLite in memory, PHP 8.5 on an Apple M4
Pro, one process:

| Operation | Time |
|---|---|
| Write, 1 000-tuple batches | ~7 ms per batch |
| Check, uncached (random document × random user) | 1.3 ms, ~24 index reads |
| Check, cached | 0.08 ms (one revision read, one cache hit) |
| 100 checks in one batch, uncached | ~110 ms |
| List-resources, first 100 of a typical user's documents | ~28 ms |
| List-resources, a user who reaches all 20 000 documents | ~290 ms |
| List-subjects, a document's users | ~1 ms |

A server database adds a network round trip per index read, so the uncached check is
dominated by that: keep the cache on, batch checks that share a subject, and pass a
consistency token only when you need the write you just made to be visible.

## Testing

`InteractsWithFineGrainedAuthorization` takes the tuple notation directly, inside an
environment:

```php
$this->actingAsEnvironment('env_test');
$this->fgaSchema($schema);
$this->fgaWrite('document:readme#viewer@user:alice');

expect($this->fgaAllows('document:readme#viewer@user:alice'))->toBeTrue();
```
