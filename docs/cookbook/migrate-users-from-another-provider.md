---
title: Migrate users from another provider
description: Bulk-import users with their existing password hashes (Auth0/Cognito/Firebase/CSV) and upgrade each hash transparently on first login
weight: 7
---

# Migrate users from another provider

Moving off Auth0, Cognito, Firebase, or a legacy SQL app usually means one of two
bad options: force every user through a password reset, or run the old system in
parallel forever. Cbox ID gives you a third: **import the users together with their
existing password hashes**, so they sign in on day one with the password they
already have — and each foreign hash is transparently re-hashed to the platform's
own hasher (argon2id) the first time they log in successfully. This is *lazy
migration*: no bulk re-hash, no reset email, no dual-run window.

The whole feature is deny-by-default and honest-crypto — see
[Custom hash verifiers](../extension-points/hash-verifiers.md) for the security
argument.

## The one call

```php
use Cbox\Id\Identity\Contracts\UserImport;
use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Identity\ValueObjects\ImportOptions;

$result = app(UserImport::class)->import($org->id, [
    // A user whose EXISTING bcrypt hash you exported from the old system.
    new ImportedUser(
        email: 'alice@acme.test',
        name: 'Alice',
        passwordHash: '$2y$12$....',   // stored verbatim, upgraded on first login
        emailVerified: true,
        role: 'member',
    ),
    // A user for whom you happen to have the plaintext (e.g. a fresh signup form):
    new ImportedUser(email: 'bob@acme.test', password: 'plain-text-pw'),
], new ImportOptions(upsert: false));

$result->imported;      // created
$result->skipped;       // already existed (no upsert)
$result->updated;       // updated (upsert)
$result->errors;        // list<ImportError>: per-row failures, run not aborted
```

- **`passwordHash`** is a *pre-hashed* credential, stored exactly as given so lazy
  migration can verify and then upgrade it. Its format must be verifiable by a
  registered [hash verifier](../extension-points/hash-verifiers.md) — natively
  bcrypt (`$2y$/$2a$/$2b$`) and argon2 (`$argon2i$/$argon2id$`).
- **`password`** is plaintext, hashed with the platform hasher immediately.
- Provide at most one of the two. Neither is fine too — the user then signs in via
  SSO, a magic link, or a password reset.

Rows are batched in a transaction per chunk, each row is atomic, and a bad row is
collected into `ImportResult::$errors` rather than aborting the run.

## From the command line

```bash
php artisan cbox-id:users:import users.csv --org=org_01H... --format=csv
```

A CSV with a header row (`email,name,password_hash,password,email_verified,role`,
plus any extra columns, which are carried through as attributes):

```csv
email,name,password_hash,password,email_verified,role
alice@acme.test,Alice,$2y$12$....,,1,member
bob@acme.test,Bob,,plain-text-pw,0,admin
```

JSON works too (`--format=json`, an array of objects with the same keys). The
command prints an imported/updated/skipped/errors summary and **exits non-zero if
any row errored**, so it fails a CI/deploy pipeline loudly. `--upsert` updates
existing users instead of skipping them.

> **`--upsert` matches by environment-wide email, not by organization.** A user
> record is unique per `(environment, email)` and can belong to several orgs in
> that environment. With `--upsert`, a row whose email already exists in the
> environment updates *that* user's name/credential and attaches them to
> `--org` — even if their real membership is another org in the same environment.
> That is why the importer is an operator-run console command with no per-org
> authorization: only run it with a file you trust for the whole environment, and
> never expose it to a single-org admin. Without `--upsert` (the default) an
> existing email is simply skipped, so a re-run is non-destructive.

## How the hash upgrades itself on login

`Subjects::verifyPassword()` runs every stored hash through the deny-by-default
hash-verifier registry. On a correct password against a foreign/legacy hash it
re-hashes the just-verified plaintext with the platform hasher and persists it in
place:

```php
$subjects = app(\Cbox\Id\Identity\Contracts\Subjects::class);

// Day one: the imported bcrypt hash authenticates immediately.
$subjects->verifyPassword($id, 's3cret'); // true

// After that login the stored hash is argon2id — re-read the row to see it.
// Every subsequent login uses the platform standard; the old format is gone.
```

There is no timing or enumeration oracle: a missing/inactive account and a wrong
password both take a full constant-cost verify, and an unrecognized hash format is
a rejection, never a silent pass.

## Foreign formats (Firebase scrypt, PBKDF2, LDAP {SSHA})

The package ships **only** the native bcrypt/argon2 verifier. A hash in any other
format is refused by default — with `ImportOptions::$rejectUnverifiableHashes`
(the default), importing such a `passwordHash` is a per-row **error**, so you can
never import a user who could never log in. To accept a foreign format for the
migration window, register your own verifier that wraps a **vetted** library — see
[Custom hash verifiers](../extension-points/hash-verifiers.md). Once those users
have logged in, their hashes are argon2id and the verifier is no longer needed.

> **Never hand-roll the hashing primitive.** Weak digests (raw md5/sha1) are not
> natively supported on purpose; a host that must accept one opts in explicitly by
> wrapping a real library, and should treat it as a short migration bridge, not a
> permanent credential store.
