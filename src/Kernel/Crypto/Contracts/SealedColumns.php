<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Contracts;

use Cbox\Id\Kernel\Crypto\ValueObjects\SealedColumn;

/**
 * The registry of every column that holds SecretBox ciphertext — the list
 * `cbox-id:crypto:rewrap` walks and `cbox-id:doctor` counts.
 *
 * Each module registers its OWN columns from its service provider, so the crypto kernel
 * never has to name a domain table, and a module that adds a sealed column cannot forget
 * a central list somewhere else. A host that seals its own secrets with the SecretBox
 * registers them here too; anything not registered is invisible to a rotation and would
 * become unreadable once its old key is dropped.
 */
interface SealedColumns
{
    public function register(SealedColumn $column): void;

    /**
     * Every registered column, in registration order, each name once.
     *
     * @return list<SealedColumn>
     */
    public function all(): array;
}
