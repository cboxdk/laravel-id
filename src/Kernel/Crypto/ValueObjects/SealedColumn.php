<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;

/**
 * One database column that holds {@see SecretBox}
 * ciphertext, described well enough to re-seal it without the module that owns it.
 *
 * Every sealed secret in the package is bound to a context of the same shape — a fixed
 * prefix plus one column of the same row (`cbox-id:webhook-endpoint:` + `id`,
 * `cbox-id:mfa:` + `user_id`, …) — so the description is declarative: no closure, no
 * model, nothing that has to boot an environment scope. The rewrap reads the row with the
 * raw query builder and rebuilds exactly the context the owning module seals with.
 *
 * A module registers its own columns ({@see SealedColumns}); a host that seals its own
 * secrets with the SecretBox registers its columns the same way and they rotate too.
 */
readonly class SealedColumn
{
    /**
     * @param  string  $table  the table name
     * @param  string  $column  the column holding the ciphertext (nullable columns are fine)
     * @param  string  $contextPrefix  the fixed part of the AEAD context
     * @param  string  $contextColumn  the column whose value completes the context
     * @param  string  $keyColumn  a unique, orderable key to walk the table by
     */
    public function __construct(
        public string $table,
        public string $column,
        public string $contextPrefix,
        public string $contextColumn = 'id',
        public string $keyColumn = 'id',
    ) {}

    /** `table.column`, the name the command and the doctor report it under. */
    public function name(): string
    {
        return $this->table.'.'.$this->column;
    }

    /** The AEAD context the owning module sealed this row's value under. */
    public function contextFor(string $contextValue): string
    {
        return $this->contextPrefix.$contextValue;
    }
}
