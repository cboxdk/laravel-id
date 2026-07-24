<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * A single row the import could not provision, and why. Collected into
 * {@see ImportResult} rather than aborting the whole run — one bad row never
 * discards the good ones.
 */
readonly class ImportError
{
    /**
     * @param  int  $row  1-based position of the row in the source stream
     * @param  string  $email  the row's email (or '' when it was the problem)
     * @param  string  $reason  a plain-language explanation
     */
    public function __construct(
        public int $row,
        public string $email,
        public string $reason,
    ) {}
}
