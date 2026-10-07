<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;

/**
 * Everything an {@see ErasureStep} needs, captured BEFORE any
 * step runs — so a step never has to read PII back from a subject row another step (or
 * the pseudonymiser) may already have overwritten.
 *
 * `email`/`name` are null when the subject store no longer knows the subject (a host that
 * already deleted its own row): the steps then clean up by id alone.
 */
readonly class ErasureRequest
{
    public function __construct(
        public string $subjectId,
        public ?string $email,
        public ?string $name,
        public SubjectPseudonym $pseudonym,
        public AuditActor $actor,
    ) {}
}
