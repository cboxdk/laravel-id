---
title: Custom hash verifiers
description: Teach the deny-by-default password-hash registry a foreign format (Firebase scrypt, PBKDF2, {SSHA}) by wrapping a vetted library
weight: 3
---

# Custom hash verifiers

Password verification for [bulk import and lazy migration](../cookbook/migrate-users-from-another-provider.md)
goes through a **deny-by-default registry** of `HashVerifier`s. The contract is
tiny:

```php
namespace Cbox\Id\Identity\Contracts;

interface HashVerifier
{
    public function supports(string $hash): bool;          // recognizes this format?
    public function verify(string $password, string $hash): bool;
    public function needsRehash(string $hash): bool;       // upgrade to the platform hasher?
}
```

The package ships exactly one implementation, `NativePasswordVerifier`, covering
the families PHP's `password_hash()` produces — bcrypt and argon2 — verified
through the vetted `password_verify` / `password_needs_rehash`. Nothing is
hand-rolled.

## The deny-by-default argument

`HashVerifierRegistry` (bound to the `HashVerifier` contract) tries each registered
verifier in order and asks the first that `supports()` the format to decide. **If
no verifier supports a hash, `verify()` returns false.** An unknown format is a
rejection, never a silent pass.

This matters because the alternative — "we don't recognize it, so let them in" —
turns a migration into a backdoor. It also means importing a user whose hash
nothing can verify is caught up front (`ImportOptions::$rejectUnverifiableHashes`,
on by default, makes it a per-row error) instead of creating an account that can
never authenticate.

## Add a format

To accept, say, Firebase's scrypt during a migration, register a verifier that
wraps a **vetted** implementation of that KDF — never a hand-written one:

```php
namespace App\Auth;

use Cbox\Id\Identity\Contracts\HashVerifier;

class FirebaseScryptVerifier implements HashVerifier
{
    public function supports(string $hash): bool
    {
        return str_starts_with($hash, 'firebase-scrypt$');
    }

    public function verify(string $password, string $hash): bool
    {
        if (! $this->supports($hash)) {
            return false; // stay deny-by-default for anything else
        }

        // Delegate to a vetted library configured with your project's
        // signer key / salt separator, and compare in constant time.
        return /* $vettedLibrary->verify($password, $hash) */;
    }

    public function needsRehash(string $hash): bool
    {
        return true; // a foreign format should always upgrade to the platform hasher
    }
}
```

Register it in `config/cbox-id.php` — it is appended after the native verifier:

```php
'hashing' => [
    'verifiers' => [
        App\Auth\FirebaseScryptVerifier::class,
    ],
],
```

That is the entire seam. Imported users with that format now sign in on day one,
and each hash is transparently re-hashed to argon2id on first successful login
(`needsRehash()` returning true drives the upgrade). Once your users have logged
in, the verifier has nothing left to do and can be removed.

> Keep a custom verifier as a short migration **bridge**, not a permanent
> credential store — and only ever back it with a maintained, vetted library.
