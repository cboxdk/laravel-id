<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\ValueObjects;

/**
 * What one action decided. Either:
 *  - CONTINUE, optionally with `enrichment` — data to fold into the operation (for
 *    the token hook: extra claims to add, reserved claims excepted); or
 *  - DENY, with a `reason` — vetoes the operation, short-circuiting the pipeline.
 */
final readonly class ActionResult
{
    /**
     * @param  array<string, mixed>  $enrichment
     */
    private function __construct(
        public bool $allowed,
        public array $enrichment,
        public string $reason,
    ) {}

    /**
     * @param  array<string, mixed>  $enrichment
     */
    public static function continue(array $enrichment = []): self
    {
        return new self(true, $enrichment, '');
    }

    public static function deny(string $reason): self
    {
        return new self(false, [], $reason);
    }
}
