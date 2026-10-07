---
title: Master key management
weight: 19
description: How secrets at rest are sealed, how the crypto master key is versioned, and how to rotate it without losing a secret
---

# Security: master key management

Every secret this package stores in a recoverable form is sealed by the `SecretBox`
(XChaCha20-Poly1305-IETF via libsodium) under one **crypto master key**,
`CBOX_ID_CRYPTO_KEY`. That covers private signing keys, TOTP secrets (subjects and
operators), vaulted downstream credentials, SSO connection configs and their client
secrets, pull-directory credentials, outbound SCIM connection secrets, webhook and
inline-hook signing secrets, and legacy-login handler secrets. Each ciphertext is
bound to its row by an AEAD context, so a value lifted from one row does not open as
another.

Signing keys rotate separately (`cbox-id:keys:rotate`); this page is about the master
key that seals them.

## The envelope names its key

Since 1.22 a sealed value looks like:

```
v1.<key-id>.<base64url(nonce ‖ ciphertext ‖ tag)>
```

`<key-id>` is a 16-hex-character **derived** id: the first 64 bits of
HMAC-SHA256 keyed with the master key over a fixed label. It is stable (the same key
always has the same id, on every host), it says nothing about the key, and nothing
has to be stored to keep it in sync. Opening a value uses exactly the key it names. A
value naming a key that is not configured fails with a message that says which key to
add back.

Values written by 1.21 and earlier carry no prefix (they are plain base64url, which
can never contain a `.`). They keep opening forever: every configured key is tried,
current first, and only the AEAD tag decides — a wrong key cannot produce a
plaintext. Both formats are pinned by frozen-envelope tests against fixed keys.

## Configuration

| Key | Env | Meaning |
|---|---|---|
| `cbox-id.crypto.key` | `CBOX_ID_CRYPTO_KEY` | The **current** key. Everything new is sealed under it. Base64, 32 bytes, optional `base64:` prefix. |
| `cbox-id.crypto.previous_keys` | `CBOX_ID_CRYPTO_PREVIOUS_KEYS` | Keys kept **only to open** values sealed before a rotation. Comma-separated, same form. Nothing is ever sealed under them. |

A malformed previous key refuses to boot with a message naming its position; the
current key re-listed among the previous ones is ignored.

## Rotating the master key

1. **Generate** a new key: `php -r "echo base64_encode(random_bytes(32)).PHP_EOL;"`.
2. **Swap**: make the new key `CBOX_ID_CRYPTO_KEY` and move the old one into
   `CBOX_ID_CRYPTO_PREVIOUS_KEYS`. Deploy. From this moment new secrets are sealed
   under the new key and old ones still open.
3. **Rewrap**: `php artisan cbox-id:crypto:rewrap`. It re-seals every registered
   column onto the current key, in bounded chunks, with progress output.
   `--dry-run` counts without writing; `--column=table.column` limits the run.
4. **Check**: `php artisan cbox-id:doctor` warns while anything is still under a
   previous key, and tells you when the previous keys are no longer needed.
5. **Drop** the old key from `CBOX_ID_CRYPTO_PREVIOUS_KEYS` only after the doctor says
   so — and keep it in your offline backup for as long as you keep database backups
   taken before the rotation.

The rewrap is safe to interrupt and re-run. It only ever selects values not yet under
the current key, walks each table by its key (so it never re-reads a value it could
not open), and writes a value back only if the row still holds exactly what it read —
a secret its owner rotated mid-run is never overwritten. It runs across **every
environment** at once: a master key is deployment-wide, so its rotation is too.

A value no configured key opens is left untouched and reported by row id; the command
exits non-zero. Do not drop a previous key while that is the case.

### What else the master key touches

The keyed OTP hasher derives its HMAC key from the **current** master key. One-time
codes already sent when you swap keys stop verifying; they live for minutes, so a
person asks for a new one. Nothing else is derived from it.

## Your own sealed columns

If your application seals its own data with the `SecretBox`, register the column so a
rotation covers it — anything unregistered keeps its old key and becomes unreadable
when that key is dropped:

```php
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;

$this->callAfterResolving(SealedColumns::class, static function (SealedColumns $columns): void {
    // Sealed with context 'acme:api-credential:'.$row->id
    $columns->register(new SealedColumn('acme_api_credentials', 'secret_encrypted', 'acme:api-credential:'));
});
```

The context must be a fixed prefix plus one column of the same row (`contextColumn`,
default `id`) — the shape every package secret uses.

## Honest scope

- **Custody is yours.** The package never stores the key; where it lives (env, a
  secrets manager, a KMS that renders it into the environment) and who can read it is
  an operator decision. Losing it makes every sealed secret unrecoverable.
- **Rotation re-seals; it does not re-key the data's meaning.** A compromised master
  key means every secret it sealed may have been read. Rotate the master key AND the
  secrets themselves (signing keys, webhook secrets, connection secrets) after a
  compromise.
- **No KMS/HSM implementation ships.** `SecretBox` is the swap point. A host that binds
  its own `SecretBox` keeps the package's rewrap working only for envelopes the
  configured keys can open.
