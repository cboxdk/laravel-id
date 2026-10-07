<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\ErasureRefused;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;

/**
 * One store's share of an erasure: remove or pseudonymise everything it holds about one
 * subject, and say what it did.
 *
 * Each module registers the steps for the data it owns ({@see ErasureSteps}); a host
 * registers steps for its own tables the same way. A step:
 *
 * - runs INSIDE the eraser's transaction — throwing aborts the whole erasure, so throw
 *   only when continuing would be wrong ({@see ErasureRefused});
 * - must be IDEMPOTENT — erasing an already-erased subject is a legitimate retry;
 * - must not depend on the subject row still holding PII: the request carries the email
 *   and name captured before anything ran, and the placeholders to write instead.
 */
interface ErasureStep
{
    /** A stable machine name, `module.thing` — it keys the receipt. */
    public function name(): string;

    public function erase(ErasureRequest $request): ErasureStepResult;
}
