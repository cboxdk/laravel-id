<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure;

use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Identity\Contracts\SubjectEraser;
use Cbox\Id\Identity\Contracts\SubjectPseudonymiser;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\ErasureReceipt;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use DateTimeImmutable;
use Illuminate\Support\Facades\DB;

/**
 * The default {@see SubjectEraser}: the registered pipeline, then the subject row, then
 * the tombstone — in one transaction.
 *
 * THE ORDER IS THE DESIGN. The email and name are read once, up front, into the
 * {@see ErasureRequest}, because several stores key personal data by email (reset
 * tokens, magic links, invitations, OTP challenges) and the subject row is the last
 * thing rewritten. The audit tombstone and the `user.erased` event come after both, so
 * neither is written for an erasure that rolled back.
 */
class DefaultSubjectEraser implements SubjectEraser
{
    public function __construct(
        private readonly ErasureSteps $steps,
        private readonly Subjects $subjects,
        private readonly SubjectPseudonymiser $pseudonymiser,
        private readonly AuditLog $audit,
        private readonly EventBus $events,
    ) {}

    public function erase(string $subjectId, ?AuditActor $actor = null): ErasureReceipt
    {
        $actor ??= AuditActor::system();
        $subject = $this->subjects->find($subjectId);

        $request = new ErasureRequest(
            subjectId: $subjectId,
            email: $subject?->email,
            name: $subject?->name,
            pseudonym: $this->pseudonymiser->pseudonymFor($subjectId),
            actor: $actor,
        );

        return DB::transaction(function () use ($request, $actor): ErasureReceipt {
            $results = [];

            foreach ($this->steps->all() as $step) {
                $results[] = $step->erase($request);
            }

            $pseudonymised = $this->pseudonymiser->pseudonymise($request->subjectId, $request->pseudonym);

            $summary = [];

            foreach ($results as $result) {
                foreach ($result->counts as $count) {
                    $summary[$result->step.'.'.$count->item] = $count->count;
                }
            }

            // The TOMBSTONE. Past entries keep the subject's opaque id — they are inside
            // the hash chain and cannot change — and this entry is what tells an auditor
            // reading them that the id now points at an erased, pseudonymised row. No PII:
            // the id, who asked, and what was removed.
            $entry = $this->audit->record(new AuditEvent(
                action: 'user.erased',
                actorType: $actor->type,
                actorId: $actor->id,
                targetType: 'user',
                targetId: $request->subjectId,
                context: ['subject_pseudonymised' => $pseudonymised, 'removed' => $summary],
            ));

            // Outbound SCIM answers this with a DELETE; webhooks fan it out.
            $this->events->emit(new DomainEvent('user.erased', ['user_id' => $request->subjectId]));

            return new ErasureReceipt(
                subjectId: $request->subjectId,
                erasedAt: new DateTimeImmutable,
                steps: $results,
                subjectPseudonymised: $pseudonymised,
                pseudonym: $request->pseudonym,
                auditEntryId: $entry->id,
            );
        });
    }
}
