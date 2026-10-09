<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

/**
 * How a pull directory's last sync went, stored on `directories.last_sync_status`.
 *
 * `Partial` is the state that needed a name: the provider answered and most people were
 * reconciled, but some records could not be (an email already owned by an unlinked account,
 * a record with no work email) or a safety check refused to deprovision. The run is not a
 * failure — joiners arrived, leavers left — and not a success an administrator can ignore.
 */
enum DirectorySyncStatus: string
{
    case Running = 'running';
    case Succeeded = 'succeeded';
    case Partial = 'partial';
    case Failed = 'failed';
}
