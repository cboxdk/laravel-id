<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\ErasureRefused;
use Cbox\Id\Identity\ValueObjects\ErasureReceipt;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;

/**
 * GDPR Art. 17 — erase a subject.
 *
 * ONE call, ONE transaction: every registered {@see ErasureStep} runs (sessions and
 * tokens revoked, credentials deleted, memberships and role grants removed, vault secrets
 * deleted, PII scrubbed from the outbox, the SCIM queue and every other store a module
 * registered), then the subject row itself is pseudonymised in place — the id is kept,
 * email and name become stable salted placeholders — and the erasure is recorded as a
 * `user.erased` audit tombstone and domain event (outbound SCIM answers it with a
 * DELETE). Either all of it happens or none of it does.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: rewrite the audit trail. Every column of an audit row
 * is inside its hash, so changing one breaks the chain for everybody after it. Past
 * entries keep the subject's opaque id, which stops being personal data once the row it
 * points at is pseudonymised — see docs/security/erasure.md for the honest limits.
 *
 * Runs in the CURRENT environment, which must be the subject's.
 */
interface SubjectEraser
{
    /**
     * @param  AuditActor|null  $actor  who asked — recorded on the tombstone; system when omitted
     *
     * @throws ErasureRefused when erasing would leave an organization with no owner
     */
    public function erase(string $subjectId, ?AuditActor $actor = null): ErasureReceipt;
}
