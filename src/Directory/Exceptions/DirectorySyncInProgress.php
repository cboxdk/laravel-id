<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

/**
 * Another sync of the same directory is already running — the scheduler and a "sync now"
 * met, or two workers picked up the same job. Refused rather than run twice: two pulls
 * racing each other's deprovisioning is how a person is deactivated by a run that started
 * before they were hired.
 *
 * A {@see DirectoryConnectionFailed}, so every caller that already tolerates a failed pull
 * tolerates this; but it is NOT recorded on the directory, because nothing is wrong with it.
 */
class DirectorySyncInProgress extends DirectoryConnectionFailed
{
    public static function for(string $directoryId): self
    {
        return new self("Directory {$directoryId} is already being synced.");
    }
}
