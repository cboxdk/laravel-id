<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * A check's answer, and the revision it was decided at.
 */
final readonly class CheckResult
{
    public function __construct(
        public Check $check,
        public bool $allowed,
        public ConsistencyToken $consistency,
    ) {}
}
