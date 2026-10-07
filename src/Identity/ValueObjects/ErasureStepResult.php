<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

use Cbox\Id\Identity\Contracts\ErasureStep;

/**
 * What one {@see ErasureStep} did. `new ErasureStepResult('x')`
 * is a valid "ran, found nothing" result; zero counts are kept, so a receipt shows a store
 * was checked rather than silently omitting it.
 */
readonly class ErasureStepResult
{
    /**
     * @param  list<ErasureCount>  $counts
     * @param  string|null  $note  a human remark — e.g. why a step could not act
     */
    public function __construct(
        public string $step,
        public array $counts = [],
        public ?string $note = null,
    ) {}

    /**
     * @param  array<string, int>  $counts  item => count, at the call site only
     */
    public static function of(string $step, array $counts, ?string $note = null): self
    {
        $list = [];

        foreach ($counts as $item => $count) {
            $list[] = new ErasureCount($item, $count);
        }

        return new self($step, $list, $note);
    }

    public function count(string $item): int
    {
        foreach ($this->counts as $count) {
            if ($count->item === $item) {
                return $count->count;
            }
        }

        return 0;
    }
}
