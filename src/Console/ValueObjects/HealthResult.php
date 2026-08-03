<?php

declare(strict_types=1);

namespace Cbox\Id\Console\ValueObjects;

use Cbox\Id\Console\Enums\HealthStatus;

/**
 * One line of the doctor's report.
 *
 * A typed value rather than the `array{status, label, detail}` the command used
 * internally: this crosses a package boundary now — the host writes these — and a
 * string-keyed map at a boundary is a shape every implementer has to guess at and
 * PHPStan cannot hold anyone to.
 */
readonly class HealthResult
{
    public function __construct(
        public HealthStatus $status,

        /** What was checked, in the operator's words rather than the code's. */
        public string $label,

        /**
         * What to DO about it. A doctor that reports "issuer misconfigured" and stops has
         * moved the problem rather than solved it; the detail is where the fix goes.
         */
        public string $detail = '',
    ) {}

    public static function ok(string $label, string $detail = ''): self
    {
        return new self(HealthStatus::Ok, $label, $detail);
    }

    public static function warn(string $label, string $detail = ''): self
    {
        return new self(HealthStatus::Warn, $label, $detail);
    }

    public static function fail(string $label, string $detail = ''): self
    {
        return new self(HealthStatus::Fail, $label, $detail);
    }
}
