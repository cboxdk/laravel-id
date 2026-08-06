<?php

declare(strict_types=1);

namespace Cbox\Id\Console\Contracts;

use Cbox\Id\Console\HealthChecks;
use Cbox\Id\Console\ValueObjects\HealthResult;

/**
 * A check `cbox-id:doctor` runs that this package could not have written.
 *
 * The doctor knows what the LIBRARY needs — extensions, a crypto key, signing keys, an
 * issuer that resolves. It cannot know what the host application needs, and the host's
 * misconfigurations are the ones that fail quietly: a deployment that says it is
 * multi-tenant with nowhere for its account console to live still boots, still serves,
 * and degrades two behaviours without an error.
 *
 * So the host contributes checks rather than shipping a second doctor. Two health
 * commands is two things to remember to run, and the one nobody runs is the one holding
 * the finding.
 *
 * @see HealthChecks the registry to add an implementation to
 */
interface HealthCheck
{
    /**
     * Run the check.
     *
     * Must not throw: a doctor that dies on its third check hides the seven after it.
     * Return a failing result instead — the whole point is to report, not to abort.
     *
     * @return list<HealthResult>
     */
    public function run(): array;
}
