<?php

declare(strict_types=1);

namespace Cbox\Id\Migration\Sources;

use Cbox\Id\Identity\Contracts\HashVerifier;
use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Migration\Contracts\LegacyCredentialSource;
use Illuminate\Database\ConnectionResolverInterface;
use InvalidArgumentException;
use Throwable;

/**
 * The old application's own users table, read directly.
 *
 * The common case by a distance: a Laravel or Rails or PHP app with a `users` table whose
 * hashes are bcrypt, sitting in a database you still have credentials for. Nothing about
 * that needs an HTTP hop — a read-only connection and a column map is the whole
 * integration, and it is fast enough to sit inside a login without anybody noticing.
 *
 * READ-ONLY BY CONSTRUCTION. This never writes to the legacy connection, not even to
 * stamp "migrated". The old system is somebody's production database during a migration
 * and the safest thing this can be is a reader — whether a person has moved is a fact
 * THIS platform owns, and it is answered by their existing here at all.
 *
 * The hash is checked by the same {@see HashVerifier} registry the platform uses for its
 * own, so a format is understood in exactly one place. A hash nothing recognises fails —
 * the registry is deny-by-default, and an unrecognised format silently passing is the one
 * outcome that would be worse than a failed migration.
 */
class DatabaseCredentialSource implements LegacyCredentialSource
{
    /**
     * @param  string  $connection  a Laravel connection name — configure it read-only
     * @param  array{email: string, name?: string, password: string, verified_at?: string}  $columns
     */
    public function __construct(
        private readonly ConnectionResolverInterface $connections,
        private readonly HashVerifier $verifier,
        private readonly string $connection,
        private readonly string $table,
        private readonly array $columns,
    ) {
        // EVERY IDENTIFIER IS VALIDATED HERE, ONCE. A table or column name from config is
        // interpolated into SQL below — `LOWER(<column>)` cannot be a bound parameter —
        // and a name nobody checked is an injection point the moment configuration is
        // writable by anything but a person. A bare identifier is the only thing this
        // integration ever needs, so anything else is refused rather than quoted.
        foreach ([$table, ...array_values($columns)] as $identifier) {
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $identifier) !== 1) {
                throw new InvalidArgumentException(
                    "Legacy database identifier [{$identifier}] is not a bare table or column name.",
                );
            }
        }
    }

    public function verify(string $email, string $password): ?ImportedUser
    {
        $row = $this->row($email);

        if ($row === null) {
            return null;
        }

        $hash = $this->string($row, $this->columns['password']);

        if ($hash === null) {
            // A row with no password — an SSO-only account in the old system, or a
            // half-created one. Not a credential we can verify, and not an error either.
            return null;
        }

        if (! $this->verifier->verify($password, $hash)) {
            return null;
        }

        return $this->toImportedUser($row, $hash);
    }

    public function find(string $email): ?ImportedUser
    {
        $row = $this->row($email);

        return $row === null
            ? null
            : $this->toImportedUser($row, $this->string($row, $this->columns['password']));
    }

    /**
     * @return array<string, mixed>|null
     */
    private function row(string $email): ?array
    {
        try {
            $row = $this->connections->connection($this->connection)
                ->table($this->table)
                // Lowercased on both sides: the old system almost certainly stored
                // whatever the person typed at signup, and a case-sensitive comparison
                // means the migration silently skips everyone who capitalised anything.
                // The identifier is validated in the constructor; the VALUE is bound.
                ->whereRaw(sprintf('LOWER(%s) = ?', $this->columns['email']), [mb_strtolower($email)]) // @phpstan-ignore-line argument.type
                ->first();
        } catch (Throwable) {
            // The connection is down, the table was renamed, credentials rotated. The
            // caller must treat this as a refusal, never as "no such user" — see the
            // fail-closed rule on the contract. Rethrowing would be the same thing said
            // louder, and this is a login path.
            return null;
        }

        if (! is_object($row)) {
            return null;
        }

        /** @var array<string, mixed> $columns */
        $columns = (array) $row;

        return $columns;
    }

    /**
     * @param  array<string, mixed>  $row
     */
    private function toImportedUser(array $row, ?string $hash): ImportedUser
    {
        $nameColumn = $this->columns['name'] ?? null;
        $verifiedColumn = $this->columns['verified_at'] ?? null;

        return new ImportedUser(
            email: (string) ($this->string($row, $this->columns['email']) ?? ''),
            name: $nameColumn !== null ? $this->string($row, $nameColumn) : null,
            // The HASH travels, never the plaintext. The person just proved they know the
            // password, and we could hash it ourselves — but carrying the original means
            // the upgrade-on-login path treats them exactly like a bulk-imported user, in
            // one code path rather than two.
            passwordHash: $hash,
            emailVerified: $verifiedColumn !== null && ($row[$verifiedColumn] ?? null) !== null,
        );
    }

    /**
     * @param  array<string, mixed>  $row
     */
    private function string(array $row, string $key): ?string
    {
        $value = $row[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
