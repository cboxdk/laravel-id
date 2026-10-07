<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

/**
 * The erasure pipeline: every {@see ErasureStep} the {@see SubjectEraser} runs, in
 * registration order.
 *
 * Modules register their own steps from their service providers, so a module that adds
 * a table of personal data adds its erasure beside it rather than in a central list
 * somebody forgets. A host does the same for its tables:
 *
 *     $this->callAfterResolving(ErasureSteps::class, fn (ErasureSteps $steps) => $steps->register(new MyStep));
 */
interface ErasureSteps
{
    /** Registering a second step with the same name replaces the first. */
    public function register(ErasureStep $step): void;

    /** @return list<ErasureStep> */
    public function all(): array;
}
