<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\ValueObjects;

/**
 * The folded result of running every action at a hook point: whether the operation
 * is allowed, the merged `enrichment` from all continuing actions (later actions
 * override earlier on the same key), and — when denied — the deciding `reason`.
 */
final readonly class PipelineOutcome
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
    public static function allow(array $enrichment = []): self
    {
        return new self(true, $enrichment, '');
    }

    public static function deny(string $reason): self
    {
        return new self(false, [], $reason);
    }
}
