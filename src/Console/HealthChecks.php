<?php

declare(strict_types=1);

namespace Cbox\Id\Console;

use Cbox\Id\Console\Contracts\HealthCheck;
use Cbox\Id\Console\ValueObjects\HealthResult;
use Throwable;

/**
 * The checks the host application contributes to `cbox-id:doctor`.
 *
 * Registered as a singleton and filled from a service provider, so the doctor stays one
 * command. A host that shipped its own health command instead would have two things to
 * remember to run, and the one nobody runs is the one holding the finding.
 */
class HealthChecks
{
    /** @var list<HealthCheck> */
    private array $checks = [];

    public function add(HealthCheck $check): void
    {
        $this->checks[] = $check;
    }

    /**
     * Run every registered check, and survive one that misbehaves.
     *
     * The contract says a check must not throw. This assumes it will anyway: a doctor
     * that dies on the host's third check hides its own findings as well as the rest of
     * the host's, and the moment you most want a health report is when something is
     * already broken enough to throw.
     *
     * @return list<HealthResult>
     */
    public function run(): array
    {
        $results = [];

        foreach ($this->checks as $check) {
            try {
                foreach ($check->run() as $result) {
                    $results[] = $result;
                }
            } catch (Throwable $e) {
                $results[] = HealthResult::fail(
                    'A health check could not run: '.$check::class,
                    $e->getMessage(),
                );
            }
        }

        return $results;
    }
}
