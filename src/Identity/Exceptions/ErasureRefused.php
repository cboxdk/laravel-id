<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * An erasure that would do more harm than it removes, refused before anything changed
 * (the eraser runs in one transaction, so a refusal from any step rolls every step back).
 */
class ErasureRefused extends RuntimeException
{
    /** @var list<string> */
    private array $organizationIds = [];

    /**
     * The subject is the only owner of these organizations. Erasing them would leave each
     * with nobody who can invite, transfer or archive — and no way back. Transfer
     * ownership first, then erase.
     *
     * @param  list<string>  $organizationIds
     */
    public static function lastOwner(array $organizationIds): self
    {
        $exception = new self(
            'The subject is the only owner of '.count($organizationIds).' organization(s) ('.implode(', ', $organizationIds).'). '
            .'Transfer ownership before erasing them.'
        );
        $exception->organizationIds = $organizationIds;

        return $exception;
    }

    /** @return list<string> the organizations blocking the erasure, for a caller to act on */
    public function organizationIds(): array
    {
        return $this->organizationIds;
    }
}
