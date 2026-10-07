<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;

/**
 * The default {@see SealedColumns}: an in-process list filled by service providers.
 * Registering the same `table.column` twice keeps the latest description, so a host can
 * re-describe a package column without it being walked twice.
 */
class SealedColumnRegistry implements SealedColumns
{
    /** @var array<string, SealedColumn> keyed by `table.column` */
    private array $columns = [];

    public function register(SealedColumn $column): void
    {
        $this->columns[$column->name()] = $column;
    }

    public function all(): array
    {
        return array_values($this->columns);
    }
}
