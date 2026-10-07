<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\SubjectPseudonym;

/**
 * Overwrites a subject's personal data ON THE SUBJECT ROW with placeholders, keeping its
 * id — the last stage of an erasure.
 *
 * The id survives on purpose: audit entries, memberships history and outbound SCIM
 * resources refer to it, and the audit chain cannot be rewritten. A pseudonymised row
 * turns every one of those references into an opaque key that points at nobody.
 *
 * The default works on the package's own users table. A host that resolves subjects
 * from its own store (`cbox-id.subject.resolver`) binds its own implementation; the
 * default then reports that it changed nothing, and the receipt says so.
 */
interface SubjectPseudonymiser
{
    /**
     * The placeholders this subject's PII becomes: deterministic for a subject (an
     * erasure retried writes the same values), unlinkable to anything without the
     * deployment's secret.
     */
    public function pseudonymFor(string $subjectId): SubjectPseudonym;

    /**
     * Replace email and name with the pseudonym, drop the password hash and the
     * verification stamp, and disable the account. True when a row was rewritten.
     */
    public function pseudonymise(string $subjectId, SubjectPseudonym $pseudonym): bool;
}
