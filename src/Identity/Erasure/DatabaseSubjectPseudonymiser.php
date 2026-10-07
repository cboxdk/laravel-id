<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure;

use Cbox\Id\Identity\Contracts\SubjectPseudonymiser;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\DatabaseSubjects;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\SubjectPseudonym;
use Cbox\Id\Kernel\Crypto\ValueObjects\MasterKeySet;

/**
 * The default {@see SubjectPseudonymiser}, over the package's own users table.
 *
 * THE PLACEHOLDER IS A KEYED HASH OF THE ID. A plain hash of a ULID could be recomputed
 * by anyone holding an audit export, which would re-link the placeholder to every entry
 * that names the id — exactly the join erasure is meant to cut. The key is
 * `cbox-id.erasure.pseudonym_key` when set, otherwise an HKDF subkey of the current
 * crypto master key; set the former if you rotate the master key and need an erasure
 * retried after the rotation to write byte-identical placeholders.
 *
 * Acts only when the default resolver is in use. A host resolving subjects from its own
 * store binds its own pseudonymiser; this one then returns false rather than write to a
 * table the host does not use.
 */
class DatabaseSubjectPseudonymiser implements SubjectPseudonymiser
{
    /** HKDF `info` for the fallback key — never reuse it for anything else. */
    private const HKDF_INFO = 'cbox-id/erasure/pseudonym/v1';

    /** Hex characters of the keyed hash kept in the placeholder (128 bits). */
    private const TOKEN_LENGTH = 32;

    public function __construct(
        private readonly Subjects $subjects,
    ) {}

    public function pseudonymFor(string $subjectId): SubjectPseudonym
    {
        return SubjectPseudonym::fromToken(substr(hash_hmac('sha256', $subjectId, $this->key()), 0, self::TOKEN_LENGTH));
    }

    public function pseudonymise(string $subjectId, SubjectPseudonym $pseudonym): bool
    {
        if (! $this->subjects instanceof DatabaseSubjects) {
            return false;
        }

        $model = $this->modelClass();

        // Written straight to the row, not through Subjects::update(): that path emits
        // `user.updated` carrying the new email, which outbound SCIM would turn into an
        // upsert that re-creates the person downstream an instant before `user.erased`
        // deletes them.
        return $model::query()->whereKey($subjectId)->update([
            'email' => $pseudonym->email,
            'name' => $pseudonym->name,
            'password' => null,
            'email_verified_at' => null,
            'status' => UserStatus::Disabled->value,
        ]) > 0;
    }

    private function key(): string
    {
        $configured = config('cbox-id.erasure.pseudonym_key');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        $master = MasterKeySet::fromConfig(config('cbox-id.crypto.key'))->current->bytes();

        return hash_hkdf('sha256', $master, 32, self::HKDF_INFO);
    }

    /** @return class-string<User> — the same resolution the default Subjects uses */
    private function modelClass(): string
    {
        $configured = config('cbox-id.models.user');

        return is_string($configured) && is_a($configured, User::class, true) ? $configured : User::class;
    }
}
