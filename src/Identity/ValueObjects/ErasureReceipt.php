<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use DateTimeImmutable;

/**
 * The record of one erasure — what was done, store by store, with counts — for the
 * controller's Art. 17 / Art. 30 paperwork and for the person who asked.
 *
 * It contains no personal data: the subject's opaque id, the placeholders written, and
 * numbers. Safe to log, store or hand back over an API.
 */
readonly class ErasureReceipt
{
    /**
     * @param  list<ErasureStepResult>  $steps
     */
    public function __construct(
        public string $subjectId,
        public DateTimeImmutable $erasedAt,
        public array $steps = [],
        public bool $subjectPseudonymised = false,
        public ?SubjectPseudonym $pseudonym = null,
        public ?string $auditEntryId = null,
    ) {}

    public function step(string $name): ?ErasureStepResult
    {
        foreach ($this->steps as $step) {
            if ($step->step === $name) {
                return $step;
            }
        }

        return null;
    }

    /** A count across the whole receipt — `count('passkeys')`. */
    public function count(string $item): int
    {
        $total = 0;

        foreach ($this->steps as $step) {
            $total += $step->count($item);
        }

        return $total;
    }

    /**
     * The serialization boundary: the receipt as plain data for JSON/API responses.
     *
     * @return array{subject_id: string, erased_at: string, subject_pseudonymised: bool, audit_entry_id: string|null, steps: list<array{step: string, counts: array<string, int>, note: string|null}>}
     */
    public function toArray(): array
    {
        $steps = [];

        foreach ($this->steps as $step) {
            $counts = [];

            foreach ($step->counts as $count) {
                $counts[$count->item] = $count->count;
            }

            $steps[] = ['step' => $step->step, 'counts' => $counts, 'note' => $step->note];
        }

        return [
            'subject_id' => $this->subjectId,
            'erased_at' => $this->erasedAt->format(DATE_ATOM),
            'subject_pseudonymised' => $this->subjectPseudonymised,
            'audit_entry_id' => $this->auditEntryId,
            'steps' => $steps,
        ];
    }
}
