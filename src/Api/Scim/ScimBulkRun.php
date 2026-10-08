<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Scim;

use Cbox\Id\Directory\Models\Directory;

/**
 * The mutable state of one `/Bulk` request while {@see DefaultScimBulkProcessor} works
 * through it: which operations have run, what each `bulkId` resolved to, how many have
 * failed, and whether `failOnErrors` has been reached.
 */
class ScimBulkRun
{
    /** @var array<int, array<string, mixed>> response entries, by operation index */
    public array $results = [];

    /** @var array<string, string> bulkId → created resource id */
    public array $resolved = [];

    /** @var array<int, true> operations whose references are being resolved (cycle guard) */
    public array $visiting = [];

    public int $errors = 0;

    public bool $stopped = false;

    /** @var array<string, int> bulkId → index of the valid POST that defines it */
    private array $definers = [];

    /**
     * @param  list<ScimBulkOperation>  $operations
     */
    public function __construct(
        public readonly Directory $directory,
        public readonly array $operations,
        public readonly ?int $failOnErrors,
    ) {
        foreach ($operations as $index => $operation) {
            if ($operation->invalid === null && $operation->method === 'POST' && $operation->bulkId !== null) {
                $this->definers[$operation->bulkId] ??= $index;
            }
        }
    }

    /**
     * The index of the valid POST that defines `$bulkId`, or null.
     */
    public function definerOf(string $bulkId): ?int
    {
        return $this->definers[$bulkId] ?? null;
    }
}
